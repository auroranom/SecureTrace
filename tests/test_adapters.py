from __future__ import annotations

from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import pytest

from securetrace.adapters import TestAdapter, PytestAdapter, get_adapter


def test_get_adapter_selects_pytest_for_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    adapter = get_adapter(tmp_path)
    assert isinstance(adapter, PytestAdapter)
    assert adapter.name == "pytest"


def test_get_adapter_rejects_missing_manifest(tmp_path: Path):
    with pytest.raises(ValueError, match="Project root must be a directory containing pyproject.toml"):
        get_adapter(tmp_path)


def test_pytest_adapter_validates_path_and_test_id(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_example.py"
    test_file.write_text("def test_ok(): pass\n", encoding="utf-8")

    adapter = get_adapter(tmp_path)
    resolved, test_id = adapter.validate_target(tmp_path, "tests/test_example.py", "test_ok")
    assert resolved == test_file.resolve()
    assert test_id == "test_ok"

    # Reject non-python file
    bad_file = tests_dir / "test_bad.php"
    bad_file.write_text("<?php", encoding="utf-8")
    with pytest.raises(ValueError, match="Only Python test files can be run"):
        adapter.validate_target(tmp_path, "tests/test_bad.php", "test_bad")

    # Reject invalid test identifier
    with pytest.raises(ValueError, match="Test identifier must name one test function"):
        adapter.validate_target(tmp_path, "tests/test_example.py", "invalid_id")


def test_pytest_adapter_command_construction(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='test'\n", encoding="utf-8")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_example.py"
    test_file.write_text("def test_ok(): pass\n", encoding="utf-8")

    adapter = PytestAdapter()
    junit_path = tmp_path / "junit.xml"
    config_path = tmp_path / "pytest.ini"

    cmd = adapter.build_command(tmp_path, test_file, "test_ok", junit_path, config_path)
    assert cmd[0] == sys.executable
    assert cmd[1:3] == ["-m", "pytest"]
    assert f"--junitxml={junit_path}" in cmd
    assert f"-c" in cmd and str(config_path) in cmd
    assert f"{test_file}::test_ok" in cmd


def test_pytest_adapter_outcome_parsing(tmp_path: Path):
    adapter = PytestAdapter()
    junit_path = tmp_path / "junit.xml"

    # 1. Exit code 0 is always PASSED
    assert adapter.parse_exit_outcome(0, junit_path) == "PASSED"

    # 2. Exit code 1 with AssertionError failure is FAILED (regression)
    junit_fail = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="0" failures="1" skipped="0" tests="1">
    <testcase classname="tests.test_auth" name="test_login">
      <failure message="assert False" type="AssertionError">assert False</failure>
    </testcase>
  </testsuite>
</testsuites>"""
    junit_path.write_text(junit_fail, encoding="utf-8")
    assert adapter.parse_exit_outcome(1, junit_path) == "FAILED"

    # 3. Exit code 1 with collection/harness error is ERROR
    junit_err = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="1" failures="0" skipped="0" tests="1">
    <testcase classname="tests.test_auth" name="test_login">
      <error message="ImportError: missing module" type="ImportError">ImportError</error>
    </testcase>
  </testsuite>
</testsuites>"""
    junit_path.write_text(junit_err, encoding="utf-8")
    assert adapter.parse_exit_outcome(1, junit_path) == "ERROR"

    # 4. Exit code 2 or missing JUnit is ERROR
    assert adapter.parse_exit_outcome(2, junit_path) == "ERROR"


def test_custom_adapter_interface_contract():
    class MockAdapter(TestAdapter):
        @property
        def name(self) -> str:
            return "mock"

        def validate_target(self, root: Path, test_file: str, test_id: str) -> tuple[Path, str]:
            return root / test_file, test_id

        def prepare_execution_artifacts(self, evidence_dir: Path) -> tuple[Path, Path | None]:
            return evidence_dir / "out.xml", None

        def build_command(self, root: Path, resolved_file: Path, test_id: str,
                          junit_path: Path, config_path: Path | None = None) -> list[str]:
            return ["mock-runner", str(resolved_file), test_id]

        def parse_exit_outcome(self, exit_code: int, junit_path: Path) -> str:
            return "PASSED" if exit_code == 0 else "FAILED"

    adapter = MockAdapter()
    assert adapter.name == "mock"
    test_path = Path("/test/t.txt")
    assert adapter.build_command(Path("/test"), test_path, "id1", Path("/tmp/x")) == ["mock-runner", str(test_path), "id1"]
