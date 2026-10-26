
from __future__ import annotations

import re
from pathlib import Path


RULES = [
    {
        "id": "PHP-CMD-001",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:shell_exec|system|passthru|exec)\s*\(",
            re.IGNORECASE,
        ),
        "title": "Potential command execution",
        "attack": (
            "If untrusted input reaches this command, an attacker "
            "may execute unintended system commands."
        ),
        "action": (
            "Review input flow; avoid shell commands or validate "
            "arguments safely."
        ),
        "extensions": {".php"},
    },
    {
        "id": "PHP-SQL-001",
        "severity": "HIGH",
        "pattern": re.compile(
            r"\b(?:mysql_query|mysqli_query)\s*\(",
            re.IGNORECASE,
        ),
        "title": "Review SQL query construction",
        "attack": (
            "A query using untrusted input may be vulnerable "
            "to SQL injection."
        ),
        "action": (
            "Use parameterized queries and review input handling."
        ),
        "extensions": {".php"},
    },
    {
        "id": "PY-SQL-001",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""execute\s*\(\s*f["']|execute\s*\(\s*["'][^"']*%s""",
            re.IGNORECASE,
        ),
        "title": "Possible SQL injection",
        "attack": "Untrusted input may influence a SQL query.",
        "action": (
            "Use parameterized queries and review input handling."
        ),
        "extensions": {".py"},
    },
    {
        "id": "SECRET-001",
        "severity": "HIGH",
        "pattern": re.compile(
            r"""(?i)\b(?:api[_-]?key|secret[_-]?key|password)\b"""
            r"""\s*[:=]\s*["'][^"'\s]{8,}["']"""
        ),
        "title": "Possible hardcoded secret",
        "attack": (
            "A real embedded credential could be exposed and misused."
        ),
        "action": (
            "Verify whether it is a real secret; rotate it if exposed."
        ),
        "extensions": {".py", ".php", ".js", ".ts", ".env"},
    },
]


# Laravel route paths worth reviewing.
SENSITIVE_ROUTE = re.compile(
    r"""(?:admin|delete|destroy|edit|update|remove)""",
    re.IGNORECASE,
)

ROUTE_DECLARATION = re.compile(
    r"""Route::(?:get|post|put|patch|delete|any|match|resource|apiResource)\s*"""
    r"""\(\s*(['"])(.*?)\1""",
    re.IGNORECASE,
)

ROUTE_MIDDLEWARE = re.compile(
    r"""->\s*middleware\s*\(""",
    re.IGNORECASE,
)

GROUP_MIDDLEWARE = re.compile(
    r"""Route::(?:middleware\s*\((.*?)\)|group\s*\((.*?)\))"""
    r""".*?->group\s*\(\s*function\b""",
    re.IGNORECASE,
)

AUTH_MARKER = re.compile(
    r"""(?:\bauth(?::[A-Za-z0-9_,.-]+)?\b"""
    r"""|\bauth:sanctum\b"""
    r"""|\bauthenticate\b"""
    r"""|\bauthorize\b"""
    r"""|\bauthorization\b"""
    r"""|\bcan:[A-Za-z0-9_.,-]+\b"""
    r"""|\bverified\b)""",
    re.IGNORECASE,
)


def _route_findings(path: Path, lines: list[str]) -> list[dict]:
    """Flag sensitive Laravel routes lacking visible protection markers.

    This is a conservative text heuristic, not a complete PHP parser.
    Middleware inherited from controllers or application configuration
    may not be visible in this file.
    """
    findings: list[dict] = []

    # Track common Route::middleware(...)->group(function () { ... )
    # scopes using brace depth.
    depth = 0
    middleware_groups: list[tuple[int, str]] = []

    for index, line in enumerate(lines):
        line_number = index + 1

        # Remove groups that have already closed.
        middleware_groups = [
            group for group in middleware_groups
            if depth >= group[0]
        ]

        group_match = GROUP_MIDDLEWARE.search(line)
        if group_match:
            declaration = group_match.group(0)
            middleware_text = group_match.group(1) or ""
            group_text = group_match.group(2) or ""
            middleware_text = f"{middleware_text} {group_text}"

            # Only suppress a warning when the group visibly declares
            # an authentication/authorization marker.
            group_protected = bool(AUTH_MARKER.search(middleware_text))
        else:
            group_protected = False

        # Count braces approximately; this supports common Laravel
        # closure groups but is not a full PHP syntax parser.
        open_braces = line.count("{")
        close_braces = line.count("}")

        if group_match and open_braces > close_braces:
            middleware_groups.append(
                (depth + open_braces - close_braces, "protected")
                if group_protected
                else (
                    depth + open_braces - close_braces,
                    "unprotected",
                )
            )

        route_match = ROUTE_DECLARATION.search(line)

        if route_match:
            route_path = route_match.group(2)

            if SENSITIVE_ROUTE.search(route_path):
                # Inspect the route statement and its chained lines.
                statement_lines = [line]
                for next_line in lines[index + 1:index + 5]:
                    statement_lines.append(next_line)
                    if ";" in next_line:
                        break

                statement = "\n".join(statement_lines)
                has_route_middleware = bool(
                    ROUTE_MIDDLEWARE.search(statement)
                )
                has_auth_marker = bool(AUTH_MARKER.search(statement))

                inside_protected_group = any(
                    kind == "protected"
                    for _, kind in middleware_groups
                )

                # If middleware is explicitly attached to the route,
                # don't claim the route is unprotected. It may use a
                # custom middleware alias we cannot interpret.
                visibly_protected = (
                    inside_protected_group
                    or has_route_middleware
                    or has_auth_marker
                )

                if not visibly_protected:
                    findings.append({
                        "rule_id": "PHP-ROUTE-001",
                        "severity": "MEDIUM",
                        "title": (
                            "Review admin or destructive route protection"
                        ),
                        "attack": (
                            "If this route lacks authentication or "
                            "authorization, an unauthorized user may "
                            "access administrative functions or modify "
                            "or delete data."
                        ),
                        "action": (
                            "Verify authentication and authorization "
                            "middleware, including inherited middleware "
                            "from route groups, controllers, and application "
                            "configuration."
                        ),
                        "file": str(path),
                        "line": line_number,
                        "evidence": line.strip()[:200],
                    })

        depth += open_braces - close_braces
        depth = max(depth, 0)

        middleware_groups = [
            group for group in middleware_groups
            if depth >= group[0]
        ]

    return findings


def scan_file(path: Path) -> list[dict]:
    """Return potential security findings in a supported source file."""
    path = Path(path)

    if not path.is_file():
        return []

    applicable_rules = [
        rule for rule in RULES
        if path.suffix.lower() in rule["extensions"]
    ]

    if not applicable_rules and path.suffix.lower() != ".php":
        return []

    try:
        lines = path.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
    except OSError:
        return []

    findings: list[dict] = []

    for line_number, line in enumerate(lines, start=1):
        for rule in applicable_rules:
            if rule["pattern"].search(line):
                findings.append({
                    "rule_id": rule["id"],
                    "severity": rule["severity"],
                    "title": rule["title"],
                    "attack": rule["attack"],
                    "action": rule["action"],
                    "file": str(path),
                    "line": line_number,
                    "evidence": line.strip()[:200],
                })

    # Apply the Laravel route heuristic only to PHP files that
    # contain route declarations.
    if path.suffix.lower() == ".php":
        if any("Route::" in line for line in lines):
            findings.extend(_route_findings(path, lines))

    return findings
