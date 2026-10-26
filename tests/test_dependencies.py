from __future__ import annotations

import os
from pathlib import Path
import subprocess
import pytest

from securetrace.db import connect, migrate_mappings
from securetrace.dependencies import (
    MAX_FILE_SIZE,
    MAX_TRAVERSAL_DEPTH,
    MAX_VISITED_NODES,
    DependencyGraph,
    build_local_dependency_graph,
    find_local_python_files,
)
from securetrace.ledger import add_requirement, analyze_change_impact, map_requirement_test


def test_dependencies_absolute_and_relative_imports(tmp_path: Path):
    (tmp_path / "helper.py").write_text("def help_func(): pass\n", encoding="utf-8")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "sub" / "worker.py").write_text(
        "from ..helper import help_func\n"
        "def do_work(): pass\n",
        encoding="utf-8",
    )
    (tmp_path / "local.py").write_text("VAL = 42\n", encoding="utf-8")
    (tmp_path / "main.py").write_text(
        "import helper\n"
        "from sub.worker import do_work\n"
        "from .local import VAL\n",
        encoding="utf-8",
    )

    graph = build_local_dependency_graph(tmp_path)
    assert "main.py" in graph.forward
    assert "helper.py" in graph.forward["main.py"]
    assert "sub/worker.py" in graph.forward["main.py"]
    assert "local.py" in graph.forward["main.py"]
    assert "helper.py" in graph.forward.get("sub/worker.py", set())

    # Reverse dependents
    assert "main.py" in graph.reverse["helper.py"]
    assert "main.py" in graph.reverse["sub/worker.py"]
    assert "main.py" in graph.reverse["local.py"]
    assert "sub/worker.py" in graph.reverse["helper.py"]


def test_dependencies_aliased_imports(tmp_path: Path):
    (tmp_path / "utils.py").write_text("def format_str(): pass\n", encoding="utf-8")
    (tmp_path / "consumer.py").write_text(
        "import utils as u\n"
        "from utils import format_str as fmt\n",
        encoding="utf-8",
    )

    graph = build_local_dependency_graph(tmp_path)
    assert graph.forward["consumer.py"] == {"utils.py"}
    assert graph.reverse["utils.py"] == {"consumer.py"}


def test_dependencies_package_init_resolution(tmp_path: Path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("EXPORT = 1\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import pkg\n", encoding="utf-8")

    graph = build_local_dependency_graph(tmp_path)
    assert "pkg/__init__.py" in graph.forward["app.py"]
    assert "app.py" in graph.reverse["pkg/__init__.py"]


def test_dependencies_transitive_chains_and_reverse_discovery(tmp_path: Path):
    # Chain: c.py -> b.py -> a.py
    (tmp_path / "c.py").write_text("DATA = 'base'\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import c\nB_VAL = c.DATA\n", encoding="utf-8")
    (tmp_path / "a.py").write_text("import b\nA_VAL = b.B_VAL\n", encoding="utf-8")

    graph = build_local_dependency_graph(tmp_path)
    dependents, paths = graph.get_transitive_dependents_with_paths("c.py")

    assert dependents == {"b.py", "a.py"}
    assert paths["b.py"] == ["c.py", "b.py"]
    assert paths["a.py"] == ["c.py", "b.py", "a.py"]


def test_dependencies_circular_imports(tmp_path: Path):
    (tmp_path / "mod1.py").write_text("import mod2\n", encoding="utf-8")
    (tmp_path / "mod2.py").write_text("import mod1\n", encoding="utf-8")

    graph = build_local_dependency_graph(tmp_path)
    assert "mod2.py" in graph.forward["mod1.py"]
    assert "mod1.py" in graph.forward["mod2.py"]

    # Traversal terminates without recursion error
    deps1 = graph.get_transitive_dependents("mod1.py")
    assert deps1 == {"mod2.py"}
    deps2 = graph.get_transitive_dependents("mod2.py")
    assert deps2 == {"mod1.py"}


def test_dependencies_missing_and_external_modules(tmp_path: Path):
    (tmp_path / "mixed.py").write_text(
        "import os\n"
        "import sys\n"
        "import pytest\n"
        "import ghost_module_never_exists_12345\n",
        encoding="utf-8",
    )

    graph = build_local_dependency_graph(tmp_path)
    assert "mixed.py" in graph.parsed_files
    records = graph.imports_by_file["mixed.py"]

    classifications = {r.module_name: r.classification for r in records}
    assert classifications["os"] == "STDLIB"
    assert classifications["sys"] == "STDLIB"
    assert classifications["pytest"] == "EXTERNAL"
    assert classifications["ghost_module_never_exists_12345"] == "UNRESOLVED"


def test_dependencies_syntax_error_and_invalid_utf8(tmp_path: Path):
    (tmp_path / "good.py").write_text("A = 1\n", encoding="utf-8")
    (tmp_path / "syntax_bad.py").write_text("def broken(:\n", encoding="utf-8")
    (tmp_path / "binary_bad.py").write_bytes(b"\x80\x81\xff\xfe\x00")

    graph = build_local_dependency_graph(tmp_path)
    assert "good.py" in graph.parsed_files
    assert "syntax_bad.py" in graph.parse_errors
    assert "binary_bad.py" in graph.parse_errors
    assert len(graph.uncertainties) >= 2


def test_dependencies_file_size_limit(tmp_path: Path):
    (tmp_path / "small.py").write_text("S = 1\n", encoding="utf-8")
    huge_file = tmp_path / "huge.py"
    # Write just over 2 MiB
    huge_file.write_bytes(b"A = 1\n" * 400000)

    graph = build_local_dependency_graph(tmp_path)
    assert "small.py" in graph.parsed_files
    assert "huge.py" not in graph.parsed_files
    assert "huge.py" in graph.parse_errors
    assert "exceeds maximum size" in graph.parse_errors["huge.py"]


def test_dependencies_path_traversal_rejection(tmp_path: Path):
    # Relative import attempting to traverse out of root
    (tmp_path / "root_file.py").write_text("from ....outside import secret\n", encoding="utf-8")

    graph = build_local_dependency_graph(tmp_path)
    records = graph.imports_by_file["root_file.py"]
    assert any(r.classification == "ESCAPE_REJECTED" for r in records)
    assert any("escapes project root" in u.lower() for u in graph.uncertainties)


def test_dependencies_symlinks_escaping_root(tmp_path: Path):
    outside_dir = tmp_path.parent / "outside_dir_sec"
    outside_dir.mkdir(exist_ok=True)
    outside_py = outside_dir / "secret.py"
    outside_py.write_text("SECRET = True\n", encoding="utf-8")

    project_dir = tmp_path / "proj"
    project_dir.mkdir()
    (project_dir / "local.py").write_text("LOCAL = True\n", encoding="utf-8")

    # Try creating symlink if OS supports it
    symlink_file = project_dir / "linked_secret.py"
    try:
        symlink_file.symlink_to(outside_py)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported in this environment")

    graph = build_local_dependency_graph(project_dir)
    assert "local.py" in graph.parsed_files
    assert "linked_secret.py" not in graph.parsed_files
    assert any("symlink escapes project root" in u.lower() for u in graph.uncertainties)


def test_dependencies_excluded_directories(tmp_path: Path):
    (tmp_path / "src.py").write_text("pass\n", encoding="utf-8")
    for excluded in [".git", ".venv", "venv", "__pycache__", "build", "dist", "node_modules", ".securetrace"]:
        d = tmp_path / excluded
        d.mkdir(exist_ok=True)
        (d / "ignored.py").write_text("pass\n", encoding="utf-8")

    found = find_local_python_files(tmp_path)
    found_posix = [p.relative_to(tmp_path).as_posix() for p in found]
    assert found_posix == ["src.py"]


def test_dependencies_max_graph_depth_and_nodes(tmp_path: Path):
    # Create linear chain of 30 files: f0 imports f1, f1 imports f2 ...
    for i in range(30):
        if i < 29:
            (tmp_path / f"file_{i:02d}.py").write_text(f"import file_{i+1:02d}\n", encoding="utf-8")
        else:
            (tmp_path / f"file_{i:02d}.py").write_text("BASE = 1\n", encoding="utf-8")

    graph = build_local_dependency_graph(tmp_path)
    dependents = graph.get_transitive_dependents("file_29.py", max_depth=MAX_TRAVERSAL_DEPTH)

    # With max_depth 25, only 25 levels of reverse dependents can be reached
    assert len(dependents) == MAX_TRAVERSAL_DEPTH


def test_change_impact_with_transitive_dependency(tmp_path: Path):
    migrate_mappings(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='transitive-demo'\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text("def test_check(): assert True\n", encoding="utf-8")

    # Dependency chain: policies.py -> authorization.py -> app.py
    (tmp_path / "policies.py").write_text("def check_owner(u, o): return u == o\n", encoding="utf-8")
    (tmp_path / "authorization.py").write_text(
        "import policies\n"
        "def authorize(u, o): return policies.check_owner(u, o)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import authorization\n"
        "def can_cancel(u, o): return authorization.authorize(u, o)\n",
        encoding="utf-8",
    )

    req = add_requirement(tmp_path, "Owner auth", "Owner verification", file_paths=["app.py"])
    map_requirement_test(tmp_path, req["id"], "tests/test_auth.py", "test_check", verification_complete=True)

    # Change only policies.py (not explicitly linked to requirement!)
    impact = analyze_change_impact(tmp_path, ["policies.py"])

    # Preserved original input
    assert impact["changed_files"] == ["policies.py"]

    # Inferred dependents discovered through static AST import graph
    assert "app.py" in impact["inferred_dependent_files"]
    assert "authorization.py" in impact["inferred_dependent_files"]

    # Linked requirement identified through transitive dependency!
    assert len(impact["requirements"]) == 1
    req_impact = impact["requirements"][0]
    assert req_impact["requirement_id"] == req["id"]
    assert req_impact["dependency_chains"] == ["policies.py -> authorization.py -> app.py"]
    assert impact["dependency_coverage"] == "LOCAL_STATIC_IMPORTS"


def test_change_impact_preserves_explicit_mappings(tmp_path: Path):
    migrate_mappings(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[project]\nname='direct-demo'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("pass\n", encoding="utf-8")

    req = add_requirement(tmp_path, "Direct link", "Direct", file_paths=["app.py"])

    # Directly changed app.py
    impact = analyze_change_impact(tmp_path, ["app.py"])
    assert impact["changed_files"] == ["app.py"]
    assert impact["inferred_dependent_files"] == []
    assert len(impact["requirements"]) == 1
    assert impact["requirements"][0]["requirement_id"] == req["id"]
    assert impact["requirements"][0].get("dependency_chains", []) == []


def test_dependencies_read_only_guarantee(tmp_path: Path, monkeypatch):
    migrate_mappings(tmp_path)
    app_file = tmp_path / "app.py"
    app_file.write_text("VAL = 100\n", encoding="utf-8")
    mtime_before = app_file.stat().st_mtime_ns

    req = add_requirement(tmp_path, "Read only", "Desc", file_paths=["app.py"])

    # Block subprocess executions
    def fail_subprocess(*args, **kwargs):
        pytest.fail("Subprocess was invoked during dependency analysis!")

    monkeypatch.setattr(subprocess, "Popen", fail_subprocess)
    monkeypatch.setattr(subprocess, "run", fail_subprocess)

    with connect(tmp_path) as db:
        checks_before = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_before = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # Run impact analysis
    impact = analyze_change_impact(tmp_path, ["app.py"])
    assert len(impact["requirements"]) == 1

    with connect(tmp_path) as db:
        checks_after = db.execute("SELECT COUNT(*) FROM checks").fetchone()[0]
        events_after = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    # Zero ledger mutations
    assert checks_after == checks_before == 0
    assert events_after == events_before
    # File content and timestamp untouched
    assert app_file.read_text(encoding="utf-8") == "VAL = 100\n"
    assert app_file.stat().st_mtime_ns == mtime_before


def test_dependencies_deterministic_output(tmp_path: Path):
    (tmp_path / "z.py").write_text("import y\n", encoding="utf-8")
    (tmp_path / "y.py").write_text("import x\n", encoding="utf-8")
    (tmp_path / "x.py").write_text("X = 1\n", encoding="utf-8")

    g1 = build_local_dependency_graph(tmp_path)
    g2 = build_local_dependency_graph(tmp_path)

    assert g1.forward == g2.forward
    assert g1.reverse == g2.reverse
    assert g1.parsed_files == g2.parsed_files
    assert g1.get_transitive_dependents("x.py") == g2.get_transitive_dependents("x.py") == {"y.py", "z.py"}
