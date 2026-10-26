
from pathlib import Path

from securetrace.ledger import add_requirement, list_requirements, record_check


def test_requirement_can_be_registered_and_retrieved(tmp_path: Path) -> None:
    requirement = add_requirement(
        tmp_path,
        title="Integration test requirement",
        description="Verify requirement registration and retrieval.",
        category="configuration",
        severity="medium",
        file_paths=["examples/securetrace-integration-test.py"],
    )

    requirements = list_requirements(tmp_path)
    retrieved = next(
        item for item in requirements if item["id"] == requirement["id"]
    )

    assert retrieved["title"] == "Integration test requirement"
    assert "examples/securetrace-integration-test.py" in retrieved["file_paths"]

    result = record_check(
        tmp_path,
        requirement["id"],
        check_name="integration-test-verification",
        passed=True,
        details="Registration and retrieval assertions passed.",
        verification_complete=True,
    )

    assert result["status"] == "VERIFIED"
