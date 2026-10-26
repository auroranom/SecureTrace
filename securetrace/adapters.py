"""Test framework adapters for SecureTrace.

Provides an internal abstraction over test execution backends (e.g. pytest,
phpunit, etc.) so that the runner's process lifecycle, timeout enforcement,
evidence hashing, and ledger persistence remain decoupled from specific test frameworks.
"""
from __future__ import annotations

import abc
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

_PYTEST_TEST_ID = re.compile(r"test_[A-Za-z0-9_]+\Z")


class TestAdapter(abc.ABC):
    """Abstract base class for test framework adapters."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Machine-readable name of the adapter."""
        ...

    @abc.abstractmethod
    def validate_target(self, root: Path, test_file: str, test_id: str) -> tuple[Path, str]:
        """Validate that the test file and test identifier conform to framework constraints."""
        ...

    @abc.abstractmethod
    def prepare_execution_artifacts(self, evidence_dir: Path) -> tuple[Path, Path | None]:
        """Create necessary temporary configuration or report files (e.g. JUnit XML target)."""
        ...

    @abc.abstractmethod
    def build_command(
        self,
        root: Path,
        resolved_file: Path,
        test_id: str,
        junit_path: Path,
        config_path: Path | None = None,
    ) -> list[str]:
        """Construct the tokenized argument list to launch the test process without shell interpolation."""
        ...

    @abc.abstractmethod
    def parse_exit_outcome(self, exit_code: int, junit_path: Path) -> str:
        """Determine test outcome (PASSED, FAILED, or ERROR) from exit code and JUnit XML."""
        ...


class PytestAdapter(TestAdapter):
    """Default adapter for Python pytest suites."""

    @property
    def name(self) -> str:
        return "pytest"

    def validate_target(self, root: Path, test_file: str, test_id: str) -> tuple[Path, str]:
        if not (root / "pyproject.toml").is_file():
            raise ValueError("Project root must be a directory containing pyproject.toml")
        if not isinstance(test_file, str) or not test_file.strip():
            raise ValueError("Test path is required")
        raw = test_file.strip().replace("\\", "/")
        path = PurePosixPath(raw)
        if path.is_absolute() or re.match(r"^[A-Za-z]:", raw) or ".." in path.parts:
            raise ValueError("Test path must be a safe project-relative path")
        if path.suffix != ".py":
            raise ValueError("Only Python test files can be run")
        parts = path.parts
        under_tests = len(parts) >= 2 and parts[0] == "tests"
        under_example_tests = len(parts) >= 4 and parts[0] == "examples" and parts[2] == "tests"
        if not (under_tests or under_example_tests):
            raise ValueError("Tests must be under tests/ or examples/<sample>/tests/")
        if not isinstance(test_id, str) or not _PYTEST_TEST_ID.fullmatch(test_id):
            raise ValueError("Test identifier must name one test function (test_name)")
        resolved = (root.joinpath(*parts)).resolve(strict=True)
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("Test path resolves outside the project root") from exc
        try:
            rel = resolved.relative_to(root).parts
        except ValueError as exc:
            raise ValueError("Test path resolves outside the project root") from exc
        if not (rel[0] == "tests" or (rel[0] == "examples" and "tests" in rel[2:])):
            raise ValueError("Resolved test path is outside an approved test directory")
        if not resolved.is_file():
            raise ValueError("Test path must be a file")
        return resolved, str(test_id)

    def prepare_execution_artifacts(self, evidence_dir: Path) -> tuple[Path, Path | None]:
        fd, junit_name = tempfile.mkstemp(prefix=".pytest-", suffix=".xml", dir=evidence_dir)
        os.close(fd)
        junit_path = Path(junit_name)

        config_fd, config_name = tempfile.mkstemp(prefix=".pytest-config-", suffix=".ini", dir=evidence_dir)
        os.close(config_fd)
        config_path = Path(config_name)
        config_path.write_text("[pytest]\n", encoding="utf-8")
        return junit_path, config_path

    def build_command(
        self,
        root: Path,
        resolved_file: Path,
        test_id: str,
        junit_path: Path,
        config_path: Path | None = None,
    ) -> list[str]:
        test_node = f"{resolved_file}::{test_id}"
        cmd = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-s",
            "--tb=short",
            "--disable-warnings",
            "--maxfail=1",
            f"--confcutdir={resolved_file.parent}",
            f"--rootdir={root}",
        ]
        if config_path is not None:
            cmd.extend(["-c", str(config_path)])
        cmd.extend([f"--junitxml={junit_path}", test_node])
        return cmd

    def parse_exit_outcome(self, exit_code: int, junit_path: Path) -> str:
        if exit_code == 0:
            return "PASSED"
        if exit_code == 1:
            try:
                root_element = ET.parse(junit_path).getroot()
                cases = root_element.findall(".//testcase")
                failures = [case.find("failure") for case in cases]
                if cases and any(
                    failure is not None
                    and (
                        failure.get("type", "").rsplit(".", 1)[-1] == "AssertionError"
                        or failure.get("message", "").startswith("AssertionError")
                        or failure.get("message", "").lstrip().startswith("assert ")
                    )
                    for failure in failures
                ):
                    return "FAILED"
            except (OSError, ET.ParseError):
                return "ERROR"
        return "ERROR"


def get_adapter(root: Path) -> TestAdapter:
    """Detect and return the appropriate TestAdapter for the given project root.

    Project detection is explicit and unambiguous:
    - Root containing pyproject.toml -> PytestAdapter
    - Missing or unconfigured project roots raise ValueError.
    """
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Project root must be a directory")

    if (root / "pyproject.toml").is_file():
        return PytestAdapter()

    raise ValueError("Project root must be a directory containing pyproject.toml")
