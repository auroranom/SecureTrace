"""Tests for Phase 2: Evidence-based assessment of proposed code changes.

Validates deterministic diff classification:
- COMMENT_ONLY
- UNRELATED_LOGIC
- MODIFIES_AUTH_LOGIC
- REMOVES_OR_WEAKENS_CHECK
- UNCERTAIN

Also validates that low-risk classifications never bypass approval policies,
and that fail-closed guarantees, plain-language warnings, and audit events are preserved.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from securetrace.approval import evaluate_proposal, load_proposal
from securetrace.db import migrate_mappings
from securetrace.diff_analysis import assess_proposed_diff
from securetrace.ledger import add_requirement, get_requirement_detail, record_check

BASE_AUTH_CODE = (
    '"""Demo authorization module."""\n\n\n'
    'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
    '    """Only the authenticated appointment owner may cancel it."""\n'
    '    return bool(actor_id) and actor_id == appointment_owner_id\n'
)


@pytest.fixture
def auth_repo(tmp_path: Path) -> tuple[Path, str]:
    app_file = tmp_path / "app.py"
    app_file.write_text(BASE_AUTH_CODE, encoding="utf-8", newline="")
    migrate_mappings(tmp_path)
    req = add_requirement(
        tmp_path,
        title="Only appointment owners can cancel",
        description="An authenticated user must not cancel an appointment owned by another user.",
        category="authorization",
        severity="high",
        file_paths=["app.py"],
    )
    req_id = req["id"]
    record_check(tmp_path, req_id, "test_owner", True, verification_complete=True)
    return tmp_path, req_id


# -----------------------------------------------------------------------------
# Unit Tests for assess_proposed_diff
# -----------------------------------------------------------------------------


def test_classification_comment_only():
    """Adding or modifying comments/docstrings yields COMMENT_ONLY with LOW risk."""
    proposed = BASE_AUTH_CODE + "\n# A harmless security comment\n"
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "COMMENT_ONLY"
    assert assessment.assessed_risk == "LOW"
    assert "comments" in assessment.summary.lower()
    assert any("identical" in e.lower() for e in assessment.evidence)


def test_classification_unrelated_logic():
    """Modifying separate functions outside authorization scope yields UNRELATED_LOGIC."""
    original = (
        f"{BASE_AUTH_CODE}\n\n"
        "def format_appointment_date(date_str: str) -> str:\n"
        "    return date_str.strip()\n"
    )
    proposed = (
        f"{BASE_AUTH_CODE}\n\n"
        "def format_appointment_date(date_str: str) -> str:\n"
        "    return f'Date: {date_str.strip()}'\n"
    )
    assessment = assess_proposed_diff(original, proposed, "app.py", [])

    assert assessment.classification == "UNRELATED_LOGIC"
    assert assessment.assessed_risk == "LOW"
    assert "format_appointment_date" in assessment.summary
    assert any("unchanged" in e.lower() or "identical" in e.lower() for e in assessment.evidence)


def test_classification_modifies_ownership_comparison():
    """Altering the comparison expression yields MODIFIES_AUTH_LOGIC with HIGH risk."""
    proposed = (
        '"""Demo authorization module."""\n\n\n'
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    """Only the authenticated appointment owner may cancel it."""\n'
        '    return bool(actor_id) and actor_id.lower() == appointment_owner_id.lower()\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "MODIFIES_AUTH_LOGIC"
    assert assessment.assessed_risk == "HIGH"
    assert any("altered" in e.lower() or "modified" in e.lower() for e in assessment.evidence)


def test_classification_removes_ownership_check_return_true():
    """Replacing the ownership check with 'return True' yields REMOVES_OR_WEAKENS_CHECK with CRITICAL risk."""
    proposed = (
        '"""Demo authorization module."""\n\n\n'
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    """Only the authenticated appointment owner may cancel it."""\n'
        '    return True\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "REMOVES_OR_WEAKENS_CHECK"
    assert assessment.assessed_risk == "CRITICAL"
    assert any("return true" in e.lower() for e in assessment.evidence)


def test_classification_removes_ownership_comparison_returning_actor_bool():
    """Removing the equality check while returning actor boolean yields REMOVES_OR_WEAKENS_CHECK."""
    proposed = (
        '"""Demo authorization module."""\n\n\n'
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    """Only the authenticated appointment owner may cancel it."""\n'
        '    return bool(actor_id)\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "REMOVES_OR_WEAKENS_CHECK"
    assert assessment.assessed_risk == "CRITICAL"
    assert any("removed" in e.lower() for e in assessment.evidence)


def test_classification_changes_and_to_or_operator():
    """Changing AND to OR allows unauthorized cancellation and yields REMOVES_OR_WEAKENS_CHECK."""
    proposed = (
        '"""Demo authorization module."""\n\n\n'
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    """Only the authenticated appointment owner may cancel it."""\n'
        '    return bool(actor_id) or actor_id == appointment_owner_id\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "REMOVES_OR_WEAKENS_CHECK"
    assert assessment.assessed_risk == "CRITICAL"
    assert any("and to or" in e.lower() for e in assessment.evidence)


def test_classification_modifies_actor_identity_validation():
    """Modifying actor validation (e.g. omitting bool(actor_id)) yields MODIFIES_AUTH_LOGIC."""
    proposed = (
        '"""Demo authorization module."""\n\n\n'
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    """Only the authenticated appointment owner may cancel it."""\n'
        '    return actor_id == appointment_owner_id\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "MODIFIES_AUTH_LOGIC"
    assert assessment.assessed_risk == "HIGH"
    assert any("actor" in e.lower() or "validation" in e.lower() for e in assessment.evidence)


def test_classification_malformed_python_is_uncertain():
    """Malformed syntax prevents confident static analysis and yields UNCERTAIN."""
    proposed = (
        'def can_cancel_appointment(actor_id, appointment_owner_id):\n'
        '    return (\n'  # SyntaxError: unexpected EOF
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "UNCERTAIN"
    assert assessment.assessed_risk == "UNCERTAIN"
    assert any("syntax error" in e.lower() for e in assessment.evidence)


def test_classification_non_python_is_uncertain():
    """Non-Python file modifications yield UNCERTAIN."""
    assessment = assess_proposed_diff("auth: true\n", "auth: false\n", "config.yaml", [])

    assert assessment.classification == "UNCERTAIN"
    assert assessment.assessed_risk == "UNCERTAIN"
    assert any("not a python source file" in e.lower() for e in assessment.evidence)


def test_classification_dynamic_code_is_uncertain():
    """Introduction of eval/exec dynamic code yields UNCERTAIN with HIGH risk."""
    proposed = (
        'def can_cancel_appointment(actor_id: str, appointment_owner_id: str) -> bool:\n'
        '    return eval(f"{actor_id} == {appointment_owner_id}")\n'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "UNCERTAIN"
    assert assessment.assessed_risk == "HIGH"
    assert any("eval" in e.lower() for e in assessment.evidence)


def test_classification_module_level_changes_are_not_assumed_unrelated():
    """Changes to module-level imports or variables are not assumed unrelated."""
    proposed = (
        'ADMIN_OVERRIDE = True\n'
        f'{BASE_AUTH_CODE}'
    )
    assessment = assess_proposed_diff(BASE_AUTH_CODE, proposed, "app.py", [])

    assert assessment.classification == "UNCERTAIN"
    assert assessment.assessed_risk == "HIGH"
    assert any("module-level" in e.lower() for e in assessment.evidence)


# -----------------------------------------------------------------------------
# Integration with Proposal Engine & Enforcement Preservation
# -----------------------------------------------------------------------------


def test_comment_only_still_requires_force_ask_review(auth_repo: tuple[Path, str]):
    """COMMENT_ONLY changes must still enforce FORCE_ASK when touching protected files."""
    root, req_id = auth_repo
    proposal = evaluate_proposal(
        root=root,
        file_path="app.py",
        operation="write",
        content=BASE_AUTH_CODE + "# harmless comment\n",
    )

    # Must NOT bypass approval policy
    assert proposal.decision == "FORCE_ASK"
    assert proposal.status == "PENDING"
    assert proposal.diff_classification == "COMMENT_ONLY"
    assert proposal.assessed_risk == "LOW"

    # Warning text reflects both registered severity and assessed risk
    warning = proposal.warning_text
    req_id = proposal.affected_requirements[0]["id"]
    assert len(warning.splitlines()) <= 12
    assert "app.py" in warning
    assert "COMMENT_ONLY" in warning
    assert "Assessed risk:** LOW" in warning
    assert f"{req_id}" in warning and "HIGH severity" in warning  # registered severity still shown
    assert "Verify with:" in warning and "test_other_user_cannot_cancel_appointment" in warning
    assert "Evidence status:" in warning
    assert "Antigravity's approval prompt" in warning and "does not approve or deny" in warning
    assert "CRITICAL" not in warning and "\U0001f6a8" not in warning  # harmless change is not alarmist


def test_weakened_check_generates_critical_warning(auth_repo: tuple[Path, str]):
    """Weakening check generates FORCE_ASK with CRITICAL assessed risk."""
    root, req_id = auth_repo
    proposal = evaluate_proposal(
        root=root,
        file_path="app.py",
        operation="edit",
        target_pattern="return bool(actor_id) and actor_id == appointment_owner_id",
        replacement_pattern="return True",
    )

    assert proposal.decision == "FORCE_ASK"
    assert proposal.status == "PENDING"
    assert proposal.diff_classification == "REMOVES_OR_WEAKENS_CHECK"
    assert proposal.assessed_risk == "CRITICAL"

    warning = proposal.warning_text
    req_id = proposal.affected_requirements[0]["id"]
    first_line = warning.splitlines()[0]
    assert "CRITICAL" in first_line and "\U0001f6a8" in first_line  # prominent heading
    assert len(warning.splitlines()) <= 12
    assert "REMOVES_OR_WEAKENS_CHECK" in warning
    assert "Assessed risk:** **CRITICAL**" in warning
    assert f"{req_id}" in warning and "HIGH severity" in warning
    assert "unauthorized users" in warning
    assert "Verify with:" in warning and "test_other_user_cannot_cancel_appointment" in warning
    assert "Antigravity's approval prompt" in warning and "does not approve or deny" in warning
    # Full evidence is not repeated in the warning but is retained on the recorded proposal.
    assert proposal.diff_evidence
    assert "return True" in "\n".join(proposal.diff_evidence) or "unconditional" in "\n".join(proposal.diff_evidence)
