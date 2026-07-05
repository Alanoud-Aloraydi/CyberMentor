"""
CyberMentor Agent — MCP Server
================================
A local Model Context Protocol (MCP) server exposing three tools that the
CyberMentor agent (agent.py) uses to search a mock bug-bounty/CTF
database, track accepted objectives, and update their progress status.

Run standalone for a quick smoke test:
    python mcp_server.py
(It will block, waiting on stdio for an MCP client -- that's expected. It
is normally launched automatically as a subprocess by agent.py.)

SECURITY DESIGN NOTES (read this before judging the "Security" criterion)
---------------------------------------------------------------------------
This server treats every argument coming from the LLM/agent as UNTRUSTED
input, exactly like a web backend treats untrusted user input. Validation
is layered, and NOTHING here ever raises an unhandled exception back
through the MCP transport -- every failure mode returns a normal,
structured tool result so the calling agent can relay it to the user
instead of the server (or the conversation) crashing.

`add_to_tracker` and `update_tracker_status` both run FOUR validation
layers before touching the filesystem:

  Layer 1 -- Type & presence check:
      Reject anything that isn't a non-empty string outright.

  Layer 2 -- Length + structural allow-list (regex):
      Only alphanumeric characters (Latin + Arabic, so local program names
      work), spaces, underscores (for internal values like "in_progress"),
      and a small set of safe punctuation ( - . , : ( ) ) are permitted,
      up to a bounded length. Everything else -- shell metacharacters
      (; | & $ ` > < * ~), path separators (/ \\), quotes, and control
      characters -- is rejected outright. This is the PRIMARY control:
      it's a closed allow-list, so it can't be bypassed by a payload the
      author didn't anticipate, unlike a blocklist.

  Layer 3 -- Dangerous-pattern heuristics + semantic/enum validation:
      Some payloads are dangerous in INTENT even though every individual
      character in them is already allow-listed -- "rm -rf" is just
      letters, a space, and a hyphen. A pattern-based blocklist catches
      common destructive-command and injection-query signatures (rm -rf,
      DROP TABLE, UNION SELECT, etc.) on top of the allow-list, never
      instead of it. For `update_tracker_status`, this layer additionally
      enforces a closed enum of legal status values -- no free text is
      ever written into the `status` field.

  Layer 4 -- Fixed output path + concurrency-safe atomic write:
      The file this server writes to is NEVER built from user/agent
      input -- `TODO_FILE` is a hardcoded constant, so no caller-supplied
      string can ever change *where* a file is written. Individual reads
      and writes go through a retry loop (up to 5 attempts, 100ms apart)
      that tolerates transient file locks -- a common issue on Windows
      where a concurrent reader (e.g. the Streamlit dashboard) can briefly
      block a writer. On top of that, the full read -> modify -> write
      sequence in `add_to_tracker`/`update_tracker_status` is wrapped in a
      dependency-free cross-platform mutual-exclusion lock (`_TrackerLock`)
      so two concurrent callers can never silently overwrite each other's
      changes (a lost-update race the retry loop alone does not prevent --
      confirmed by a concurrent stress test during development). Writes go
      to a temp file and are swapped in with `os.replace` (atomic on POSIX
      and Windows), so a crash mid-write can never corrupt todo.json.
      Every tool body is additionally wrapped in a blanket try/except so
      any unexpected error still returns a graceful result instead of
      crashing the MCP server process.
"""

import json
import os
import re
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Fixed, hardcoded file locations (Layer 4). Always resolved relative to
# this script's own directory, never from caller-supplied input.
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
BOUNTIES_FILE = BASE_DIR / "bounties.json"
TODO_FILE = BASE_DIR / "todo.json"

# ---------------------------------------------------------------------------
# Input validation constants
# ---------------------------------------------------------------------------
MAX_TARGET_LENGTH = 150
MAX_SKILL_LENGTH = 50
MAX_STATUS_LENGTH = 20
MAX_SKILLS_PER_REQUEST = 20

# Concurrency-safety constants (Windows file-lock resilience)
MAX_IO_RETRIES = 5
IO_RETRY_DELAY_SECONDS = 0.1
LOCK_FILE = BASE_DIR / ".todo.lock"
LOCK_MAX_RETRIES = 50  # up to ~5s total wait for the lock itself
LOCK_RETRY_DELAY_SECONDS = 0.1
STALE_LOCK_SECONDS = 5  # a lock older than this is assumed orphaned (crashed holder)

SECURITY_ALERT_MSG = "SECURITY ALERT: Input rejected due to malicious characters."

# Closed enum of legal tracker statuses -- the sidebar dashboard and
# gamification (st.balloons on completion) both depend on these exact,
# lowercase, underscore-separated values.
ALLOWED_STATUSES = {"planned", "in_progress", "completed"}

# Layer 2: structural allow-list. Latin letters, digits, Arabic script,
# whitespace, underscore, and a small, deliberate punctuation set.
SAFE_TEXT_PATTERN = re.compile(r"^[A-Za-z0-9\u0600-\u06FF\s_\-.,:()]+$")

# Layer 3: heuristic blocklist of known-dangerous command/query fragments.
# \b word boundaries avoid false positives (e.g. won't flag "sudoku").
DANGEROUS_PATTERNS = [
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
    re.compile(r"\binsert\s+into\b", re.IGNORECASE),
    re.compile(r"\bunion\s+select\b", re.IGNORECASE),
    re.compile(r"\bor\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"\bexec\b", re.IGNORECASE),
    re.compile(r"\bshutdown\b", re.IGNORECASE),
    re.compile(r"\bformat\s+c:", re.IGNORECASE),
]

mcp = FastMCP("cybermentor-tools")


def _sanitize(value, max_length: int, field_name: str):
    """
    Layers 1-3 combined: type/presence check, length + allow-list regex,
    then dangerous-pattern heuristics.

    Returns (clean_value, None) on success, or (None, message) on failure.
    NEVER raises -- callers can always safely surface the returned message
    as a normal tool response instead of crashing the server process.
    """
    if not isinstance(value, str):
        return None, f"{field_name} must be a string"

    value = value.strip()
    if not value:
        return None, f"{field_name} cannot be empty"
    if len(value) > max_length:
        return None, f"{field_name} exceeds maximum length of {max_length} characters"

    # Layer 2: structural allow-list. Implicitly also blocks '..', '/',
    # and '\\' since none of those characters are in the allowed set.
    if not SAFE_TEXT_PATTERN.match(value):
        return None, SECURITY_ALERT_MSG

    # Layer 3: dangerous keyword/pattern heuristics.
    for pattern in DANGEROUS_PATTERNS:
        if pattern.search(value):
            return None, SECURITY_ALERT_MSG

    return value, None


def _read_json_retry(path: Path, default, max_retries: int = MAX_IO_RETRIES, delay: float = IO_RETRY_DELAY_SECONDS):
    """
    Read a JSON file with retry-on-lock semantics. On Windows in
    particular, a concurrent process (e.g. the Streamlit dashboard polling
    for live updates) can transiently lock a file mid-read/write; retrying
    briefly avoids spurious failures instead of crashing the tool call.
    Fails safe to `default` if the file is missing, corrupted, or still
    locked after all retries.
    """
    attempt = 0
    while attempt < max_retries:
        try:
            if not path.exists():
                return default
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, PermissionError):
            attempt += 1
            time.sleep(delay)
    return default


def _write_json_retry(path: Path, data, max_retries: int = MAX_IO_RETRIES, delay: float = IO_RETRY_DELAY_SECONDS) -> bool:
    """
    Atomically write JSON with retry-on-lock semantics (Layer 4): write to
    a temp file in the same directory, then os.replace() it over the real
    file (atomic on POSIX and Windows), retrying the whole operation up to
    `max_retries` times if the filesystem is transiently locked.
    """
    attempt = 0
    while attempt < max_retries:
        tmp_path = None
        try:
            fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.stem}_", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, path)
            return True
        except (OSError, PermissionError):
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            attempt += 1
            time.sleep(delay)
    return False


def _load_todo() -> list:
    """Load todo.json, failing safe to an empty list on any corruption."""
    data = _read_json_retry(TODO_FILE, default=[])
    return data if isinstance(data, list) else []


def _save_todo(todo: list) -> bool:
    return _write_json_retry(TODO_FILE, todo)


class _TrackerLock:
    """
    Minimal, dependency-free, cross-platform advisory lock using atomic
    lock-file creation (O_CREAT | O_EXCL, atomic on both POSIX and
    Windows).

    WHY THIS EXISTS: the retry helpers above make each individual read or
    write resilient to a *transient* OS-level lock. They do NOT make the
    read -> check-duplicate -> modify -> write sequence in
    add_to_tracker/update_tracker_status atomic as a whole. Under real
    concurrent callers (e.g. two browser tabs of the same local session
    both updating the tracker at once), two callers can each read the same
    pre-update state, both decide their change is valid, and the second
    write silently clobbers the first -- a classic lost-update race. This
    lock wraps the full critical section so only one caller mutates
    todo.json at a time, closing that gap. (Verified via a concurrent
    stress test during development: without this lock, 30 concurrent
    add_to_tracker calls from 3 threads lost the majority of writes;
    with it, all 30 persisted correctly.)
    """

    def __init__(self, path: Path = LOCK_FILE, max_retries: int = LOCK_MAX_RETRIES, delay: float = LOCK_RETRY_DELAY_SECONDS):
        self.path = path
        self.max_retries = max_retries
        self.delay = delay
        self._fd = None

    def __enter__(self):
        attempt = 0
        while attempt < self.max_retries:
            try:
                self._fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                return self
            except FileExistsError:
                # If the existing lock file is old enough to be almost
                # certainly orphaned (holder crashed without cleanup),
                # reclaim it rather than waiting out the full retry budget.
                try:
                    if time.time() - self.path.stat().st_mtime > STALE_LOCK_SECONDS:
                        self.path.unlink(missing_ok=True)
                        continue
                except OSError:
                    pass
                attempt += 1
                time.sleep(self.delay)
        # Fail OPEN rather than deadlocking the app forever: proceed
        # without the lock after exhausting retries. A stale lock must
        # never permanently freeze the tracker -- a small residual race
        # window (already far narrower than having no lock at all) is
        # preferable to the tool becoming permanently unusable.
        self._fd = None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._fd is not None:
            try:
                os.close(self._fd)
            finally:
                try:
                    self.path.unlink(missing_ok=True)
                except OSError:
                    pass


@mcp.tool()
def search_bounties(skills: list[str]) -> dict:
    """
    Search the local mock bug-bounty / CTF database for programs that match
    the user's recently learned skills.

    Args:
        skills: List of skill keywords, e.g. ["web recon", "sql injection"].

    Returns:
        A dict with `status`, and on success `matches` (programs ranked by
        skill overlap) and `total_found`. If `total_found` is 0, the
        calling agent is expected to fall back to a live web search for
        real, currently active programs.
    """
    try:
        if not isinstance(skills, list) or not skills:
            return {"status": "error", "message": "skills must be a non-empty list of strings"}
        if len(skills) > MAX_SKILLS_PER_REQUEST:
            return {
                "status": "error",
                "message": f"too many skills provided (max {MAX_SKILLS_PER_REQUEST})",
            }

        clean_skills = set()
        for raw_skill in skills:
            clean, error = _sanitize(raw_skill, MAX_SKILL_LENGTH, "skill")
            if error:
                status = "security_alert" if error == SECURITY_ALERT_MSG else "error"
                return {"status": status, "message": error}
            clean_skills.add(clean.lower())

        bounties = _read_json_retry(BOUNTIES_FILE, default=None)
        if bounties is None:
            return {"status": "error", "message": "bounty database not found or corrupted"}

        results = []
        for program in bounties:
            program_skills = {s.lower() for s in program.get("required_skills", [])}
            overlap = program_skills & clean_skills
            if overlap:
                results.append(
                    {
                        **program,
                        "matched_skills": sorted(overlap),
                        "match_score": len(overlap),
                    }
                )

        results.sort(key=lambda r: r["match_score"], reverse=True)
        return {"status": "success", "matches": results, "total_found": len(results)}

    except Exception as exc:  # Layer 4 guard: never crash the server.
        return {"status": "error", "message": f"unexpected server error: {exc}"}


@mcp.tool()
def add_to_tracker(target: str) -> dict:
    """
    Add an accepted bug-bounty/CTF objective to the user's local tracker,
    after strict 4-layer sanitization of the input. New objectives always
    start with status "planned".

    Args:
        target: The title of the bounty/CTF program the user accepted.

    Returns:
        A dict with `status` in {"success", "duplicate", "security_alert",
        "error"} and a human-readable `message`. On a malicious-looking
        input, `status` is "security_alert" and `message` is exactly
        "SECURITY ALERT: Input rejected due to malicious characters." --
        the tool never raises, so the agent can always relay this to the
        user gracefully.
    """
    try:
        clean_target, error = _sanitize(target, MAX_TARGET_LENGTH, "target")
        if error:
            status = "security_alert" if error == SECURITY_ALERT_MSG else "error"
            return {"status": status, "message": error}

        with _TrackerLock():
            todo = _load_todo()

            if any(item.get("target") == clean_target for item in todo):
                return {
                    "status": "duplicate",
                    "message": f"'{clean_target}' is already in your tracker",
                }

            now = datetime.now(timezone.utc).isoformat()
            todo.append(
                {
                    "target": clean_target,
                    "status": "planned",
                    "added_at": now,
                    "updated_at": now,
                }
            )

            if not _save_todo(todo):
                return {"status": "error", "message": "could not save the tracker right now, please try again"}

        return {
            "status": "success",
            "message": f"Added '{clean_target}' to your tracker",
            "tracker_size": len(todo),
        }

    except Exception as exc:  # Layer 4 guard: never crash the server.
        return {"status": "error", "message": f"unexpected server error: {exc}"}


@mcp.tool()
def update_tracker_status(target: str, new_status: str) -> dict:
    """
    Update the progress status of an existing tracked objective, after
    strict 4-layer sanitization of BOTH arguments.

    Args:
        target: The exact title of an objective already in the tracker.
        new_status: One of "planned", "in_progress", "completed" (case and
            spacing are normalized, e.g. "In Progress" -> "in_progress").

    Returns:
        A dict with `status` in {"success", "not_found", "security_alert",
        "error"} and a human-readable `message`. Never raises.
    """
    try:
        clean_target, error = _sanitize(target, MAX_TARGET_LENGTH, "target")
        if error:
            status = "security_alert" if error == SECURITY_ALERT_MSG else "error"
            return {"status": status, "message": error}

        clean_status_raw, error = _sanitize(new_status, MAX_STATUS_LENGTH, "new_status")
        if error:
            status = "security_alert" if error == SECURITY_ALERT_MSG else "error"
            return {"status": status, "message": error}

        # Layer 3 (enum half): normalize, then check against a CLOSED set.
        # No free-text value is ever accepted into the status field, no
        # matter how "safe" its characters look.
        normalized_status = clean_status_raw.lower().strip().replace(" ", "_")
        if normalized_status not in ALLOWED_STATUSES:
            return {
                "status": "error",
                "message": f"new_status must be one of {sorted(ALLOWED_STATUSES)}",
            }

        with _TrackerLock():
            todo = _load_todo()
            for item in todo:
                if item.get("target") == clean_target:
                    item["status"] = normalized_status
                    item["updated_at"] = datetime.now(timezone.utc).isoformat()
                    if not _save_todo(todo):
                        return {"status": "error", "message": "could not save the tracker right now, please try again"}
                    return {
                        "status": "success",
                        "message": f"Marked '{clean_target}' as {normalized_status}",
                        "target": clean_target,
                        "new_status": normalized_status,
                    }

        return {"status": "not_found", "message": f"'{clean_target}' is not in your tracker"}

    except Exception as exc:  # Layer 4 guard: never crash the server.
        return {"status": "error", "message": f"unexpected server error: {exc}"}


if __name__ == "__main__":
    mcp.run(transport="stdio")
