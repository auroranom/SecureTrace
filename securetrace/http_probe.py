"""Structured HTTP probe foundation for SecureTrace.

Provides safe, loopback-restricted HTTP probe specification, response evaluation,
sensitive data redaction, and outcome classification (VULNERABLE, SECURE_FOR_THIS_CHECK,
and INCONCLUSIVE).

Guarantees:
- Targets are strictly bounded to local loopback (127.0.0.1, localhost, [::1]).
- External URLs, arbitrary protocols, credentials in URLs, and non-safe HTTP methods are rejected.
- Redirects to external hosts are detected and marked INCONCLUSIVE rather than followed blindly.
- HTTP 200 alone does not prove vulnerability without matching protected content indicators.
- Redirect/401/403 alone does not prove comprehensive requirement verification (verification_complete is strictly False).
- Response bodies, PII, donor records, session cookies, and authorization tokens are never stored in evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import re
import socket
import urllib.error
from urllib.parse import urlparse, urljoin
import urllib.request

_REQUIREMENT_ID = re.compile(r"SEC-[A-F0-9]{8}\Z")
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})
_ALLOWED_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
_SENSITIVE_HEADER_NAMES = frozenset({
    "set-cookie",
    "cookie",
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "x-csrf-token",
    "x-xsrf-token",
})
_SAFE_HEADER_NAMES = frozenset({
    "content-type",
    "location",
    "content-length",
    "server",
    "date",
    "cache-control",
})


class ProbeVerdict(str, Enum):
    """Granular verdict of a single HTTP probe."""

    VULNERABLE = "VULNERABLE"
    SECURE_FOR_THIS_CHECK = "SECURE_FOR_THIS_CHECK"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass(frozen=True)
class HttpProbeSpec:
    """Validated, loopback-only probe specification."""

    requirement_id: str
    target_url: str
    method: str = "GET"
    timeout_seconds: float = 5.0
    expected_unauthenticated_indicators: tuple[str, ...] = field(default_factory=tuple)
    expected_auth_redirect_prefixes: tuple[str, ...] = field(default_factory=lambda: ("/login", "http://127.0.0.1", "http://localhost"))

    def __post_init__(self) -> None:
        if not isinstance(self.requirement_id, str) or not _REQUIREMENT_ID.fullmatch(self.requirement_id):
            raise ValueError("Requirement ID must match SEC- followed by eight uppercase hexadecimal characters")

        if self.method.upper() not in _ALLOWED_METHODS:
            raise ValueError(f"Method must be one of {sorted(_ALLOWED_METHODS)}, got '{self.method}'")
        object.__setattr__(self, "method", self.method.upper())

        if not (0.1 <= self.timeout_seconds <= 30.0):
            raise ValueError("timeout_seconds must be between 0.1 and 30.0")

        parsed = urlparse(self.target_url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Target URL scheme must be http or https")

        if parsed.username or parsed.password:
            raise ValueError("Target URL must not contain embedded user credentials")

        hostname = (parsed.hostname or "").lower()
        if hostname not in _ALLOWED_HOSTS:
            raise ValueError(
                f"Target URL must bind strictly to local loopback (127.0.0.1, localhost, [::1]), got '{hostname}'"
            )

        if not parsed.port:
            raise ValueError("Target URL must specify an explicit port (e.g. http://127.0.0.1:8000/path)")

        if not (1 <= parsed.port <= 65535):
            raise ValueError("Port must be between 1 and 65535")

        if ".." in parsed.path:
            raise ValueError("Path must not contain traversal elements ('..')")


@dataclass(frozen=True)
class ProbeEvaluationResult:
    """Outcome and safe evidence metadata for an evaluated probe response."""

    verdict: ProbeVerdict
    status_code: int
    explanation: str
    safe_headers: dict[str, str]
    body_byte_count: int
    body_sha256: str
    matched_indicators: tuple[str, ...]
    ledger_outcome: str
    verification_complete: bool = False

    def to_provenance(self, spec: HttpProbeSpec) -> dict:
        """Return a privacy-safe provenance dictionary suitable for SecureTrace ledger."""
        parsed = urlparse(spec.target_url)
        return {
            "probe_target": {
                "host": parsed.hostname,
                "port": parsed.port,
                "path": parsed.path,
                "method": spec.method,
            },
            "probe_verdict": self.verdict.value,
            "status_code": self.status_code,
            "explanation": self.explanation,
            "safe_headers": self.safe_headers,
            "body_byte_count": self.body_byte_count,
            "body_sha256": self.body_sha256,
            "matched_indicators": list(self.matched_indicators),
            "verification_complete": self.verification_complete,
        }


def redact_headers(raw_headers: dict[str, str]) -> dict[str, str]:
    """Filter headers to a safe whitelist, strictly redacting cookies, auth headers, and secrets."""
    safe: dict[str, str] = {}
    for name, value in raw_headers.items():
        lower_name = name.lower()
        if lower_name in _SENSITIVE_HEADER_NAMES:
            continue
        if lower_name in _SAFE_HEADER_NAMES:
            safe[lower_name] = value.strip()
    return safe


def evaluate_probe_response(
    spec: HttpProbeSpec,
    status_code: int,
    headers: dict[str, str],
    body: str | bytes,
) -> ProbeEvaluationResult:
    """Evaluate an HTTP response safely according to security invariants.

    Rules:
    1. 401 Unauthorized / 403 Forbidden:
       -> SECURE_FOR_THIS_CHECK (ledger: PASSED, verification_complete: False)
    2. 301/302/303/307/308 Redirect:
       - If redirect target is external -> INCONCLUSIVE (ledger: ERROR)
       - If redirect target is login/auth endpoint -> SECURE_FOR_THIS_CHECK (ledger: PASSED, verification_complete: False)
       - If redirect target is unexpected -> INCONCLUSIVE (ledger: ERROR)
    3. 200 OK:
       - If expected_unauthenticated_indicators match -> VULNERABLE (ledger: FAILED, verification_complete: False)
       - If indicators do not match or none configured -> INCONCLUSIVE (ledger: ERROR)
         (200 alone NEVER proves vulnerability without positive evidence of protected content)
    4. 5xx Server Error / other:
       -> INCONCLUSIVE (ledger: ERROR)
    """
    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    body_text = body if isinstance(body, str) else body.decode("utf-8", errors="replace")
    body_sha256 = hashlib.sha256(body_bytes).hexdigest()
    byte_count = len(body_bytes)
    safe_hdr = redact_headers(headers)

    # 1. Access denied
    if status_code in (401, 403):
        return ProbeEvaluationResult(
            verdict=ProbeVerdict.SECURE_FOR_THIS_CHECK,
            status_code=status_code,
            explanation=f"Unauthenticated request was rejected with HTTP {status_code}.",
            safe_headers=safe_hdr,
            body_byte_count=byte_count,
            body_sha256=body_sha256,
            matched_indicators=(),
            ledger_outcome="PASSED",
            verification_complete=False,
        )

    # 2. Redirect
    if status_code in (301, 302, 303, 307, 308):
        location = headers.get("Location") or headers.get("location") or ""
        if not location:
            return ProbeEvaluationResult(
                verdict=ProbeVerdict.INCONCLUSIVE,
                status_code=status_code,
                explanation="Redirect response without Location header.",
                safe_headers=safe_hdr,
                body_byte_count=byte_count,
                body_sha256=body_sha256,
                matched_indicators=(),
                ledger_outcome="ERROR",
                verification_complete=False,
            )

        # Check for external redirect
        resolved_loc = urljoin(spec.target_url, location)
        loc_parsed = urlparse(resolved_loc)
        loc_host = (loc_parsed.hostname or "").lower()
        if loc_host and loc_host not in _ALLOWED_HOSTS:
            return ProbeEvaluationResult(
                verdict=ProbeVerdict.INCONCLUSIVE,
                status_code=status_code,
                explanation=f"Redirect to external host '{loc_host}' detected; aborting.",
                safe_headers=safe_hdr,
                body_byte_count=byte_count,
                body_sha256=body_sha256,
                matched_indicators=(),
                ledger_outcome="ERROR",
                verification_complete=False,
            )

        # Check if redirect matches expected login / auth destination
        loc_lower = location.lower()
        is_auth_redirect = any(
            prefix.lower() in loc_lower for prefix in spec.expected_auth_redirect_prefixes
        ) or "login" in loc_lower or "auth" in loc_lower

        if is_auth_redirect:
            return ProbeEvaluationResult(
                verdict=ProbeVerdict.SECURE_FOR_THIS_CHECK,
                status_code=status_code,
                explanation=f"Unauthenticated request was redirected to login: '{location}'.",
                safe_headers=safe_hdr,
                body_byte_count=byte_count,
                body_sha256=body_sha256,
                matched_indicators=(),
                ledger_outcome="PASSED",
                verification_complete=False,
            )

        return ProbeEvaluationResult(
            verdict=ProbeVerdict.INCONCLUSIVE,
            status_code=status_code,
            explanation=f"Redirected to unexpected location '{location}'.",
            safe_headers=safe_hdr,
            body_byte_count=byte_count,
            body_sha256=body_sha256,
            matched_indicators=(),
            ledger_outcome="ERROR",
            verification_complete=False,
        )

    # 3. HTTP 200
    if status_code == 200:
        if not spec.expected_unauthenticated_indicators:
            return ProbeEvaluationResult(
                verdict=ProbeVerdict.INCONCLUSIVE,
                status_code=200,
                explanation="HTTP 200 received but no protected content indicators were specified to confirm data exposure.",
                safe_headers=safe_hdr,
                body_byte_count=byte_count,
                body_sha256=body_sha256,
                matched_indicators=(),
                ledger_outcome="ERROR",
                verification_complete=False,
            )

        matched = tuple(
            indicator for indicator in spec.expected_unauthenticated_indicators
            if indicator in body_text
        )

        if matched:
            return ProbeEvaluationResult(
                verdict=ProbeVerdict.VULNERABLE,
                status_code=200,
                explanation=f"HTTP 200 exposed protected content matching indicators: {list(matched)}.",
                safe_headers=safe_hdr,
                body_byte_count=byte_count,
                body_sha256=body_sha256,
                matched_indicators=matched,
                ledger_outcome="FAILED",
                verification_complete=False,
            )

        return ProbeEvaluationResult(
            verdict=ProbeVerdict.INCONCLUSIVE,
            status_code=200,
            explanation="HTTP 200 received but response body did not match expected protected content indicators.",
            safe_headers=safe_hdr,
            body_byte_count=byte_count,
            body_sha256=body_sha256,
            matched_indicators=(),
            ledger_outcome="ERROR",
            verification_complete=False,
        )

    # 4. Server error or unexpected status
    return ProbeEvaluationResult(
        verdict=ProbeVerdict.INCONCLUSIVE,
        status_code=status_code,
        explanation=f"Unexpected response status code HTTP {status_code}.",
        safe_headers=safe_hdr,
        body_byte_count=byte_count,
        body_sha256=body_sha256,
        matched_indicators=(),
        ledger_outcome="ERROR",
        verification_complete=False,
    )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not auto-follow redirects; capture redirect response directly so probe can evaluate location safely."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def dispatch_probe(
    spec: HttpProbeSpec,
    opener: urllib.request.OpenerDirector | None = None,
    max_body_bytes: int = 65_536,
) -> ProbeEvaluationResult:
    """Safely dispatch the HTTP probe against the loopback target without auto-following redirects."""
    if opener is None:
        opener = urllib.request.build_opener(_NoRedirectHandler)

    req = urllib.request.Request(
        spec.target_url,
        method=spec.method,
        headers={"User-Agent": "SecureTrace-Probe/1.0", "Accept": "text/html,application/xhtml+xml"},
    )
    try:
        with opener.open(req, timeout=spec.timeout_seconds) as resp:
            status_code = getattr(resp, "status", None) or resp.getcode()
            headers = dict(resp.headers.items())
            raw_body = resp.read(max_body_bytes)
            return evaluate_probe_response(spec, status_code, headers, raw_body)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        headers = dict(exc.headers.items()) if exc.headers else {}
        try:
            raw_body = exc.read(max_body_bytes)
        except Exception:
            raw_body = b""
        return evaluate_probe_response(spec, status_code, headers, raw_body)
    except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError, OSError) as exc:
        reason = getattr(exc, "reason", str(exc))
        return ProbeEvaluationResult(
            verdict=ProbeVerdict.INCONCLUSIVE,
            status_code=0,
            explanation=f"Probe connection failed: {reason}",
            safe_headers={},
            body_byte_count=0,
            body_sha256="",
            matched_indicators=(),
            ledger_outcome="ERROR",
            verification_complete=False,
        )
