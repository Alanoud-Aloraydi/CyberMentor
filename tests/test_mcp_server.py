"""
Tests for the CyberMentor MCP server (mcp_server.py).

These turn the README's "verified during development" security and
concurrency claims into an automated, always-runnable suite: the 4-layer
input sanitization, the full tracker CRUD (search / add / update / remove),
and the lost-update race that the tracker lock is there to prevent.

Every test points TODO_FILE / BOUNTIES_FILE at a temp directory, so the
real todo.json and bounties.json are never touched.
"""

import json
import threading

import pytest

import mcp_server as m


@pytest.fixture
def tracker(tmp_path, monkeypatch):
    """Redirect all data files to a temp dir and return the temp todo path."""
    todo = tmp_path / "todo.json"
    bounties = tmp_path / "bounties.json"
    bounties.write_text(
        json.dumps(
            [
                {"title": "Test Web Bounty", "required_skills": ["web recon", "xss"]},
                {"title": "Test API Bounty", "required_skills": ["api security", "idor"]},
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(m, "TODO_FILE", todo)
    monkeypatch.setattr(m, "BOUNTIES_FILE", bounties)
    # _TrackerLock captures LOCK_FILE as a frozen default argument at import
    # time, so patching the module constant alone doesn't move the lock file.
    # Redirect the default too, keeping all file I/O in the fast temp dir.
    lock = tmp_path / ".todo.lock"
    monkeypatch.setattr(m, "LOCK_FILE", lock)
    monkeypatch.setattr(
        m._TrackerLock.__init__,
        "__defaults__",
        (lock, m.LOCK_MAX_RETRIES, m.LOCK_RETRY_DELAY_SECONDS),
    )
    return todo


# ---------------------------------------------------------------------------
# Layer 1-3: _sanitize
# ---------------------------------------------------------------------------

def test_sanitize_accepts_clean_text():
    value, error = m._sanitize("web recon", m.MAX_SKILL_LENGTH, "skill")
    assert error is None
    assert value == "web recon"


def test_sanitize_accepts_arabic():
    value, error = m._sanitize("اختبار", m.MAX_SKILL_LENGTH, "skill")
    assert error is None
    assert value == "اختبار"


def test_sanitize_rejects_non_string():
    value, error = m._sanitize(123, m.MAX_SKILL_LENGTH, "skill")
    assert value is None and error is not None


def test_sanitize_rejects_empty():
    value, error = m._sanitize("   ", m.MAX_SKILL_LENGTH, "skill")
    assert value is None and "empty" in error


def test_sanitize_rejects_too_long():
    value, error = m._sanitize("a" * 999, m.MAX_SKILL_LENGTH, "skill")
    assert value is None and "length" in error


@pytest.mark.parametrize("payload", ["foo; ls", "a/b", "back\\slash", "$(whoami)", "a`b`", "a|b", "a>b"])
def test_sanitize_blocks_shell_metacharacters(payload):
    value, error = m._sanitize(payload, m.MAX_TARGET_LENGTH, "target")
    assert value is None
    assert error == m.SECURITY_ALERT_MSG


@pytest.mark.parametrize("payload", ["rm -rf tmp", "DROP TABLE users", "UNION SELECT pw", "sudo reboot"])
def test_sanitize_blocks_dangerous_patterns(payload):
    value, error = m._sanitize(payload, m.MAX_TARGET_LENGTH, "target")
    assert value is None
    assert error == m.SECURITY_ALERT_MSG


# ---------------------------------------------------------------------------
# search_bounties
# ---------------------------------------------------------------------------

def test_search_bounties_matches(tracker):
    result = m.search_bounties(["xss"])
    assert result["status"] == "success"
    assert result["total_found"] == 1
    assert result["matches"][0]["title"] == "Test Web Bounty"


def test_search_bounties_no_match(tracker):
    result = m.search_bounties(["cryptography"])
    assert result["status"] == "success"
    assert result["total_found"] == 0


def test_search_bounties_rejects_empty_list(tracker):
    assert m.search_bounties([])["status"] == "error"


def test_search_bounties_rejects_too_many(tracker):
    assert m.search_bounties(["s"] * (m.MAX_SKILLS_PER_REQUEST + 1))["status"] == "error"


# ---------------------------------------------------------------------------
# add_to_tracker
# ---------------------------------------------------------------------------

def test_add_success_and_persists(tracker):
    result = m.add_to_tracker("Test Web Bounty")
    assert result["status"] == "success"
    saved = json.loads(tracker.read_text(encoding="utf-8"))
    assert len(saved) == 1
    assert saved[0]["target"] == "Test Web Bounty"
    assert saved[0]["status"] == "planned"


def test_add_duplicate(tracker):
    m.add_to_tracker("Objective A")
    result = m.add_to_tracker("Objective A")
    assert result["status"] == "duplicate"
    assert len(json.loads(tracker.read_text(encoding="utf-8"))) == 1


def test_add_security_alert(tracker):
    result = m.add_to_tracker("hack; rm -rf /")
    assert result["status"] == "security_alert"
    assert not tracker.exists() or json.loads(tracker.read_text(encoding="utf-8")) == []


# ---------------------------------------------------------------------------
# update_tracker_status
# ---------------------------------------------------------------------------

def test_update_success(tracker):
    m.add_to_tracker("Objective B")
    result = m.update_tracker_status("Objective B", "In Progress")  # normalized
    assert result["status"] == "success"
    saved = json.loads(tracker.read_text(encoding="utf-8"))
    assert saved[0]["status"] == "in_progress"


def test_update_not_found(tracker):
    assert m.update_tracker_status("Nope", "completed")["status"] == "not_found"


def test_update_rejects_invalid_status(tracker):
    m.add_to_tracker("Objective C")
    assert m.update_tracker_status("Objective C", "abandoned")["status"] == "error"


# ---------------------------------------------------------------------------
# remove_from_tracker  (the new feature)
# ---------------------------------------------------------------------------

def test_remove_success(tracker):
    m.add_to_tracker("Objective D")
    result = m.remove_from_tracker("Objective D")
    assert result["status"] == "success"
    assert json.loads(tracker.read_text(encoding="utf-8")) == []


def test_remove_not_found(tracker):
    assert m.remove_from_tracker("Ghost")["status"] == "not_found"


def test_remove_security_alert(tracker):
    assert m.remove_from_tracker("x; DROP TABLE y")["status"] == "security_alert"


def test_remove_leaves_others_intact(tracker):
    m.add_to_tracker("Keep 1")
    m.add_to_tracker("Delete Me")
    m.add_to_tracker("Keep 2")
    m.remove_from_tracker("Delete Me")
    saved = {i["target"] for i in json.loads(tracker.read_text(encoding="utf-8"))}
    assert saved == {"Keep 1", "Keep 2"}


# ---------------------------------------------------------------------------
# Concurrency: the tracker lock must prevent lost updates
# (the exact scenario the README describes as verified in development)
# ---------------------------------------------------------------------------

def test_concurrent_adds_are_not_lost(tracker):
    # Mirrors the scenario documented in the README: 30 add_to_tracker
    # calls spread across 3 threads (each thread does 10 sequential adds).
    # Without the tracker lock this loses the majority of writes; with it,
    # every one of the 30 objectives must persist.
    threads_count = 3
    per_thread = 10
    threads = []

    def worker(thread_id):
        for j in range(per_thread):
            m.add_to_tracker(f"Objective T{thread_id}-{j:02d}")

    for t_id in range(threads_count):
        threads.append(threading.Thread(target=worker, args=(t_id,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    saved = json.loads(tracker.read_text(encoding="utf-8"))
    total = threads_count * per_thread
    assert len(saved) == total
    assert len({i["target"] for i in saved}) == total
