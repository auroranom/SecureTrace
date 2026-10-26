from __future__ import annotations

import hashlib
import http.client
import json
from pathlib import Path
import sqlite3
from threading import Thread
from contextlib import contextmanager

import pytest

from securetrace.dashboard import answer_question, create_server, read_dashboard_data
from securetrace.ledger import add_requirement, mark_changed_files, record_check


@contextmanager
def dashboard_client(root: Path):
    server = create_server(root, port=0)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def post(path: str, payload: dict):
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request(
            "POST", path, body=json.dumps(payload),
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        result = response.status, json.loads(response.read())
        connection.close()
        return result

    try:
        yield post
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def make_sample_ledger(root: Path) -> str:
    item = add_requirement(
        root,
        "Only owners can cancel appointments",
        "The backend verifies appointment ownership.",
        category="authorization",
        severity="high",
        file_paths=["src/routes/appointments.py"],
    )
    record_check(
        root,
        item["id"],
        "owner-authorization-test",
        passed=True,
        details="Tested the authenticated owner path.",
        verification_complete=True,
    )
    mark_changed_files(root, ["src/routes/appointments.py"])
    return item["id"]


def make_one_requirement_per_status(root: Path) -> None:
    identified = add_requirement(root, "Identified requirement", "Awaiting implementation.")
    implemented = add_requirement(root, "Implemented requirement", "Partial check recorded.")
    record_check(root, implemented["id"], "partial-check", passed=True)
    verified = add_requirement(root, "Verified requirement", "Complete check recorded.")
    record_check(root, verified["id"], "complete-check", passed=True, verification_complete=True)
    stale = add_requirement(root, "Stale requirement", "Linked evidence changed.", file_paths=["stale.py"])
    record_check(root, stale["id"], "complete-check", passed=True, verification_complete=True)
    mark_changed_files(root, ["stale.py"])
    regression = add_requirement(root, "Regression requirement", "Failing check recorded.")
    record_check(root, regression["id"], "failing-check", passed=False)


def test_dashboard_snapshot_counts_and_report_are_read_only(tmp_path: Path, monkeypatch):
    requirement_id = make_sample_ledger(tmp_path)
    db_path = tmp_path / ".securetrace" / "securetrace.db"
    before = hashlib.sha256(db_path.read_bytes()).digest()

    # A snapshot render must not fall back to the regular ledger APIs.
    import securetrace.reporting as reporting

    def forbidden(*args, **kwargs):
        raise AssertionError("snapshot report attempted to access ledger APIs")

    monkeypatch.setattr(reporting, "list_requirements", forbidden)
    monkeypatch.setattr(reporting, "get_requirement_detail", forbidden)
    data = read_dashboard_data(tmp_path)

    assert data["total"] == 1
    assert data["counts"] == {
        "IDENTIFIED": 0, "IMPLEMENTED": 0, "VERIFIED": 0,
        "STALE": 1, "REGRESSION": 0,
    }
    assert data["requirements"][0]["file_paths"] == ["src/routes/appointments.py"]
    assert data["details"][requirement_id]["checks"][0]["result"] == "PASSED"
    assert "SecureTrace Security Report" in data["report"]
    assert "not proof that the entire application is secure" in data["report"]
    assert hashlib.sha256(db_path.read_bytes()).digest() == before


def test_chat_explains_stale_status_from_recorded_event_and_check(tmp_path: Path):
    requirement_id = make_sample_ledger(tmp_path)
    response = answer_question(read_dashboard_data(tmp_path), f"Why is {requirement_id} stale?")

    assert requirement_id in response
    assert "STALE" in response
    assert "LINKED_FILE_CHANGED" not in response  # User-facing explanation uses the ledger event details.
    assert "src/routes/appointments.py" in response
    assert "owner-authorization-test — PASSED" in response
    assert "Tested the authenticated owner path." in response
    assert "does not guarantee that the application is secure" in response


def test_chat_reports_no_match_from_actual_ledger(tmp_path: Path):
    make_sample_ledger(tmp_path)
    response = answer_question(read_dashboard_data(tmp_path), "Why is SEC-UNKNOWN stale?")
    assert "couldn't match" in response


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("How many requirements are tracked?", "5 requirements are tracked"),
        ("How many are stale?", "1 requirement is stale"),
        (
            "How many requirements are tracked, and how many are stale?",
            "5 requirements are tracked and 1 requirement is stale",
        ),
        (
            "Show counts for all five statuses.",
            "IDENTIFIED: 1, IMPLEMENTED: 1, VERIFIED: 1, STALE: 1, REGRESSION: 1",
        ),
    ],
)
def test_chat_answers_aggregate_questions_from_ledger(tmp_path: Path, question: str, expected: str):
    make_one_requirement_per_status(tmp_path)
    data = read_dashboard_data(tmp_path)
    db_path = tmp_path / ".securetrace" / "securetrace.db"
    before = hashlib.sha256(db_path.read_bytes()).digest()

    response = answer_question(data, question)

    assert expected in response
    assert hashlib.sha256(db_path.read_bytes()).digest() == before


def test_dashboard_http_endpoints_and_local_bind(tmp_path: Path):
    requirement_id = make_sample_ledger(tmp_path)
    server = create_server(tmp_path, port=0)
    assert server.server_address[0] == "127.0.0.1"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("GET", "/")
        response = connection.getresponse()
        page = response.read().decode("utf-8")
        assert response.status == 200
        assert "SecureTrace Dashboard" in page
        assert "Ask about the ledger" in page
        assert "Add Requirement" in page
        assert "Record Check Evidence" in page
        assert "does not execute a security test" in page
        assert "Generate Security Report" in page
        assert '<pre id="report">' in page

        connection.request("GET", "/api/dashboard")
        response = connection.getresponse()
        dashboard = json.loads(response.read())
        assert response.status == 200
        assert dashboard["requirements"][0]["id"] == requirement_id

        connection.request(
            "POST", "/api/chat", body=json.dumps({"question": f"Why is {requirement_id} stale?"}),
            headers={"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        answer = json.loads(response.read())["answer"]
        assert response.status == 200
        assert "src/routes/appointments.py" in answer

        database = tmp_path / ".securetrace" / "securetrace.db"
        before = hashlib.sha256(database.read_bytes()).digest()
        connection.request("GET", "/api/report")
        response = connection.getresponse()
        report = json.loads(response.read())["report"]
        assert response.status == 200
        assert "SecureTrace Security Report" in report
        assert "Only owners can cancel appointments" in report
        assert "not proof that the entire application is secure" in report
        assert hashlib.sha256(database.read_bytes()).digest() == before

        connection.request("GET", "/api/report?format=anything")
        response = connection.getresponse()
        assert response.status == 404
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_dashboard_actions_update_ledger_and_keep_database_integrity(tmp_path: Path):
    with dashboard_client(tmp_path) as post:
        status, body = post("/api/actions/add-requirement", {
            "confirmed": True,
            "title": "Only owners can update records",
            "description": "The server checks record ownership.",
            "category": "authorization",
            "severity": "high",
            "file_paths": ["src/records.py"],
        })
        assert status == 200
        requirement_id = body["result"]["id"]
        assert body["data"]["counts"]["IDENTIFIED"] == 1
        assert requirement_id in body["data"]["report"]

        status, body = post("/api/actions/record-check", {
            "confirmed": True,
            "requirement_id": requirement_id,
            "check_name": "owner-authorization-test",
            "details": "Manually recorded after reviewing test output.",
            "result": "PASSED",
            "verification_complete": True,
        })
        assert status == 200
        assert body["data"]["requirements"][0]["status"] == "VERIFIED"
        assert "did not execute a test" in body["message"]

        status, body = post("/api/actions/mark-changed-files", {
            "confirmed": True,
            "file_paths": ["src/records.py"],
        })
        assert status == 200
        assert body["result"] == [{
            "requirement_id": requirement_id, "changed_files": ["src/records.py"],
            "mapped_tests": [], "verification_plan": [], "eligible_reruns": [], "unmapped": True,
            "evidence_stale": False, "evidence_freshness": "UNKNOWN", "historical_runs_preserved": 1,
            "uncertainty": "No approved test mapping is available; rerun eligibility cannot be determined.",
        }]
        assert body["data"]["requirements"][0]["status"] == "STALE"
        assert f"- **Status:** STALE" in body["data"]["report"]
        assert requirement_id in body["message"]

        status, body = post("/api/actions/record-check", {
            "confirmed": True,
            "requirement_id": requirement_id,
            "check_name": "owner-authorization-test",
            "details": "A failure was manually recorded.",
            "result": "FAILED",
            "verification_complete": False,
        })
        assert status == 200
        assert body["data"]["counts"]["REGRESSION"] == 1
        assert body["data"]["counts"]["STALE"] == 0

    database = tmp_path / ".securetrace" / "securetrace.db"
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)
    try:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        connection.close()


def test_dashboard_action_validation_confirmation_and_fixed_routes(tmp_path: Path):
    with dashboard_client(tmp_path) as post:
        status, body = post("/api/actions/add-requirement", {
            "title": "Missing confirmation", "description": "Not written.",
            "category": "other", "severity": "medium", "file_paths": [],
        })
        assert status == 400
        assert "Confirm" in body["error"]
        assert not (tmp_path / ".securetrace" / "securetrace.db").exists()

        base = {
            "confirmed": True, "title": "Safe path validation",
            "description": "Reject escaping paths.", "category": "other",
            "severity": "medium",
        }
        status, body = post("/api/actions/add-requirement", {**base, "file_paths": ["../outside.py"]})
        assert status == 400
        assert "Path traversal" in body["error"]

        status, body = post("/api/actions/add-requirement", {**base, "category": "not-a-category", "file_paths": []})
        assert status == 400
        assert "Category" in body["error"]

        status, body = post("/api/actions/record-check", {
            "confirmed": True, "requirement_id": "SEC-NOTFOUND", "check_name": "bad-result",
            "result": "EXECUTE", "verification_complete": False,
        })
        assert status == 400
        assert "PASSED or FAILED" in body["error"]

        status, body = post("/api/actions/mark-changed-files", {
            "confirmed": True, "file_paths": ["folder/../../outside.py"],
        })
        assert status == 400
        assert "Path traversal" in body["error"]

        status, body = post("/api/actions/arbitrary-function", {"confirmed": True, "name": "anything"})
        assert status == 404
        assert not (tmp_path / ".securetrace" / "securetrace.db").exists()


def test_dashboard_does_not_initialize_a_missing_database(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        read_dashboard_data(tmp_path)
    assert not (tmp_path / ".securetrace").exists()
