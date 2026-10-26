from __future__ import annotations

import pytest

from securetrace.http_probe import (
    HttpProbeSpec,
    ProbeVerdict,
    ProbeEvaluationResult,
    dispatch_probe,
    evaluate_probe_response,
    redact_headers,
)


def test_spec_validates_requirement_id():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )
    assert spec.requirement_id == "SEC-4236736E"

    with pytest.raises(ValueError, match="Requirement ID must match SEC-"):
        HttpProbeSpec(requirement_id="INVALID-123", target_url="http://127.0.0.1:8090/doner")


def test_spec_validates_allowed_methods():
    spec_get = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        method="get",
    )
    assert spec_get.method == "GET"

    spec_head = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        method="HEAD",
    )
    assert spec_head.method == "HEAD"

    with pytest.raises(ValueError, match="Method must be one of"):
        HttpProbeSpec(
            requirement_id="SEC-4236736E",
            target_url="http://127.0.0.1:8090/doner",
            method="POST",
        )


def test_spec_strictly_enforces_loopback():
    # Loopback targets are allowed
    for host in ("127.0.0.1", "localhost"):
        spec = HttpProbeSpec(
            requirement_id="SEC-4236736E",
            target_url=f"http://{host}:8090/doner",
        )
        assert host in spec.target_url

    # External hosts must be rejected
    for bad_url in (
        "http://example.com:8090/doner",
        "http://192.168.1.50:8090/doner",
        "https://attacker.site:443/doner",
        "ftp://127.0.0.1:8090/doner",
    ):
        with pytest.raises(ValueError):
            HttpProbeSpec(requirement_id="SEC-4236736E", target_url=bad_url)


def test_spec_rejects_credentials_and_traversal():
    with pytest.raises(ValueError, match="embedded user credentials"):
        HttpProbeSpec(
            requirement_id="SEC-4236736E",
            target_url="http://admin:secret@127.0.0.1:8090/doner",
        )

    with pytest.raises(ValueError, match="traversal"):
        HttpProbeSpec(
            requirement_id="SEC-4236736E",
            target_url="http://127.0.0.1:8090/admin/../doner",
        )


def test_spec_requires_explicit_port():
    with pytest.raises(ValueError, match="explicit port"):
        HttpProbeSpec(
            requirement_id="SEC-4236736E",
            target_url="http://127.0.0.1/doner",
        )


def test_redact_headers_removes_sensitive():
    raw_headers = {
        "Set-Cookie": "session=sensitive_cookie_value_123; HttpOnly",
        "Authorization": "Bearer secret-token-xyz",
        "X-CSRF-Token": "csrf-secret-abc",
        "Content-Type": "text/html; charset=UTF-8",
        "Location": "http://127.0.0.1:8090/login",
        "Server": "PHP/8.3.33 Development Server",
    }
    redacted = redact_headers(raw_headers)
    assert "set-cookie" not in redacted
    assert "authorization" not in redacted
    assert "x-csrf-token" not in redacted
    assert redacted.get("content-type") == "text/html; charset=UTF-8"
    assert redacted.get("location") == "http://127.0.0.1:8090/login"
    assert redacted.get("server") == "PHP/8.3.33 Development Server"


def test_evaluate_access_denied_returns_secure_for_this_check():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )
    for code in (401, 403):
        res = evaluate_probe_response(
            spec,
            status_code=code,
            headers={"Content-Type": "text/html"},
            body="<html>Access Denied</html>",
        )
        assert res.verdict == ProbeVerdict.SECURE_FOR_THIS_CHECK
        assert res.ledger_outcome == "PASSED"
        assert res.verification_complete is False


def test_evaluate_login_redirect_returns_secure_for_this_check():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )
    res = evaluate_probe_response(
        spec,
        status_code=302,
        headers={"Location": "http://127.0.0.1:8090/login"},
        body="",
    )
    assert res.verdict == ProbeVerdict.SECURE_FOR_THIS_CHECK
    assert res.ledger_outcome == "PASSED"
    assert res.verification_complete is False


def test_evaluate_external_redirect_returns_inconclusive():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )
    res = evaluate_probe_response(
        spec,
        status_code=302,
        headers={"Location": "https://external-auth.example.com/login"},
        body="",
    )
    assert res.verdict == ProbeVerdict.INCONCLUSIVE
    assert res.ledger_outcome == "ERROR"
    assert res.verification_complete is False


def test_evaluate_200_with_matching_indicator_returns_vulnerable():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        expected_unauthenticated_indicators=("Donor List", "<table", "eshwar_admin"),
    )
    donor_html = """<html><body>
    <div class="eshwar_admin">
      <h1>Donor List</h1>
      <table><tr><td>John Doe</td><td>$500</td></tr></table>
    </div>
    </body></html>"""
    res = evaluate_probe_response(
        spec,
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=donor_html,
    )
    assert res.verdict == ProbeVerdict.VULNERABLE
    assert res.ledger_outcome == "FAILED"
    assert res.verification_complete is False
    assert "Donor List" in res.matched_indicators
    assert "<table" in res.matched_indicators


def test_evaluate_200_without_indicator_returns_inconclusive():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        expected_unauthenticated_indicators=("Donor List",),
    )
    # Generic or custom 404 page returning 200
    generic_html = "<html><body>Page Not Found</body></html>"
    res = evaluate_probe_response(
        spec,
        status_code=200,
        headers={"Content-Type": "text/html"},
        body=generic_html,
    )
    assert res.verdict == ProbeVerdict.INCONCLUSIVE
    assert res.ledger_outcome == "ERROR"
    assert res.verification_complete is False


def test_evaluate_server_error_returns_inconclusive():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )
    res = evaluate_probe_response(
        spec,
        status_code=500,
        headers={"Content-Type": "text/plain"},
        body="Internal Server Error",
    )
    assert res.verdict == ProbeVerdict.INCONCLUSIVE
    assert res.ledger_outcome == "ERROR"


def test_to_provenance_never_stores_body_or_pii():
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        expected_unauthenticated_indicators=("Donor List",),
    )
    donor_html = "<h1>Donor List</h1><p>Donor Name: Alice, Amount: 1000, Card: 4111222233334444</p>"
    res = evaluate_probe_response(
        spec,
        status_code=200,
        headers={"Content-Type": "text/html", "Set-Cookie": "auth_cookie=secret"},
        body=donor_html,
    )
    provenance = res.to_provenance(spec)

    # Verify sensitive data is NOT present in provenance
    serialized = str(provenance)
    assert "Alice" not in serialized
    assert "1000" not in serialized
    assert "4111222233334444" not in serialized
    assert "auth_cookie" not in serialized
    assert "secret" not in serialized

    # Metadata is present
    assert provenance["probe_verdict"] == "VULNERABLE"
    assert provenance["status_code"] == 200
    assert provenance["body_byte_count"] == len(donor_html.encode("utf-8"))
    assert provenance["verification_complete"] is False


def test_dispatch_probe_handles_connection_error():
    # Attempting to contact a closed local port must return INCONCLUSIVE without crashing
    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:59999/doner",
        timeout_seconds=0.5,
    )
    res = dispatch_probe(spec)
    assert res.verdict == ProbeVerdict.INCONCLUSIVE
    assert res.status_code == 0
    assert "failed" in res.explanation.lower()
    assert res.ledger_outcome == "ERROR"


def test_dispatch_probe_handles_mocked_http_error(monkeypatch):
    import urllib.error
    import io

    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
    )

    class FakeOpener:
        def open(self, req, timeout=None):
            fp = io.BytesIO(b"Forbidden")
            raise urllib.error.HTTPError(
                req.full_url, 403, "Forbidden", {"Content-Type": "text/plain"}, fp
            )

    res = dispatch_probe(spec, opener=FakeOpener())
    assert res.verdict == ProbeVerdict.SECURE_FOR_THIS_CHECK
    assert res.status_code == 403
    assert res.ledger_outcome == "PASSED"
    assert res.verification_complete is False


def test_dispatch_probe_handles_mocked_success(monkeypatch):
    import io

    spec = HttpProbeSpec(
        requirement_id="SEC-4236736E",
        target_url="http://127.0.0.1:8090/doner",
        expected_unauthenticated_indicators=("Donor List",),
    )

    class FakeResponse:
        status = 200
        headers = {"Content-Type": "text/html"}

        def read(self, limit=None):
            return b"<h1>Donor List</h1><table><tr><td>Data</td></tr></table>"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeOpener:
        def open(self, req, timeout=None):
            return FakeResponse()

    res = dispatch_probe(spec, opener=FakeOpener())
    assert res.verdict == ProbeVerdict.VULNERABLE
    assert res.status_code == 200
    assert res.ledger_outcome == "FAILED"
    assert res.verification_complete is False
