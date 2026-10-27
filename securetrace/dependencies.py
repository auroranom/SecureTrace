"""Static local Python dependency analysis based on AST parsing.

This module inspects local Python import graphs strictly without executing
application code, external interpreters, or runtime imports.
"""
from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field, replace
import importlib.util
from pathlib import Path
import re
import sys

# Maximum file size to inspect (2 MiB)
MAX_FILE_SIZE: int = 2 * 1024 * 1024

# Traversal bounds
MAX_TRAVERSAL_DEPTH: int = 25
MAX_VISITED_NODES: int = 500

# Standard directories excluded from static analysis
DEFAULT_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    ".securetrace",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "eggs",
    ".eggs",
})


def _normalize_path(path: str | Path) -> str:
    """Normalize a path to a project-relative POSIX string without leading ./."""
    return Path(path).as_posix().removeprefix("./")


@dataclass(frozen=True)
class ImportRecord:
    """Raw import statement metadata extracted from an AST."""
    raw_name: str
    imported_names: tuple[str, ...]
    is_relative: bool
    level: int
    line_number: int


@dataclass(frozen=True)
class ResolvedImport:
    """An import statement resolved against the local project filesystem."""
    source_file: str
    module_name: str
    target_file: str | None
    classification: str  # "LOCAL", "STDLIB", "EXTERNAL", "UNRESOLVED", "ESCAPE_REJECTED"
    detail: str = ""
    imported_names: tuple[str, ...] = ()


@dataclass
class DependencyGraph:
    """Directed graph representing local Python import relationships."""
    root: Path
    # forward: source_file -> set of local target files it imports
    forward: dict[str, set[str]] = field(default_factory=dict)
    # reverse: target_file -> set of local source files that import it (dependents)
    reverse: dict[str, set[str]] = field(default_factory=dict)
    # detailed resolved imports per source file
    imports_by_file: dict[str, list[ResolvedImport]] = field(default_factory=dict)
    # files parsed successfully
    parsed_files: set[str] = field(default_factory=set)
    # parse or filesystem errors: file -> error message
    parse_errors: dict[str, str] = field(default_factory=dict)
    # dynamic import patterns detected: file -> list of warnings
    dynamic_import_warnings: dict[str, list[str]] = field(default_factory=dict)
    # analysis uncertainties (unresolved imports, warnings, errors)
    uncertainties: list[str] = field(default_factory=list)
    # Structured incompleteness, keyed by the source file whose edges are not fully known.
    # Each entry: {"kind": "UNPARSEABLE"|"DYNAMIC_IMPORT"|"UNRESOLVED_IMPORT", "detail": str,
    # "tokens": [names an unresolved import could be satisfied by]}. Used to decide whether
    # incompleteness can plausibly affect a registered requirement (see ledger.analyze_change_impact).
    incomplete_sources: dict[str, list[dict]] = field(default_factory=dict)
    # Start files whose dependent traversal hit the depth/node bound (results are then a lower bound).
    truncated_traversals: set[str] = field(default_factory=set)

    def _note_incomplete(self, source: str, kind: str, detail: str, tokens: tuple[str, ...] = ()) -> None:
        self.incomplete_sources.setdefault(source, []).append(
            {"kind": kind, "detail": detail, "tokens": list(tokens)}
        )

    def get_direct_dependencies(self, file_path: str) -> set[str]:
        """Return the local files directly imported by file_path."""
        return set(self.forward.get(_normalize_path(file_path), set()))

    def get_direct_dependents(self, file_path: str) -> set[str]:
        """Return the local files that directly import file_path."""
        return set(self.reverse.get(_normalize_path(file_path), set()))

    def get_transitive_dependents(
        self,
        file_path: str,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> set[str]:
        """Return all local files that transitively depend on file_path."""
        dependents, _ = self.get_transitive_dependents_with_paths(file_path, max_depth, max_nodes)
        return dependents

    def get_transitive_dependents_with_paths(
        self,
        file_path: str,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> tuple[set[str], dict[str, list[str]]]:
        """Return transitive dependents and the shortest dependency chain leading to each.

        Bounds are read at call time. If a bound cuts the traversal short the start
        file is recorded in ``truncated_traversals``: the result is then only a lower
        bound and callers must not treat missing dependents as proof of absence.

        Returns:
            A tuple of (set of dependent file paths, mapping of dependent -> [chain of files]).
        """
        max_depth = MAX_TRAVERSAL_DEPTH if max_depth is None else max_depth
        max_nodes = MAX_VISITED_NODES if max_nodes is None else max_nodes
        start = _normalize_path(file_path)
        visited: set[str] = set()
        paths_to: dict[str, list[str]] = {}
        queue: deque[tuple[str, int, list[str]]] = deque()

        # Initialize with direct dependents
        for direct in sorted(self.reverse.get(start, set())):
            if direct != start:
                queue.append((direct, 1, [start, direct]))

        while queue and len(visited) < max_nodes:
            current, depth, path = queue.popleft()
            if current in visited or current == start:
                continue
            visited.add(current)
            if current not in paths_to:
                paths_to[current] = path

            if depth < max_depth:
                for nxt in sorted(self.reverse.get(current, set())):
                    if nxt in visited or nxt == start:
                        continue
                    if len(visited) + len(queue) < max_nodes:
                        queue.append((nxt, depth + 1, path + [nxt]))
                    else:
                        self.truncated_traversals.add(start)
            elif any(n not in visited and n != start for n in self.reverse.get(current, set())):
                self.truncated_traversals.add(start)

        if queue:
            self.truncated_traversals.add(start)
        return visited, paths_to

    def get_transitive_dependencies(
        self,
        file_path: str,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> set[str]:
        """Return all local files that file_path transitively imports."""
        dependencies, _ = self.get_transitive_dependencies_with_paths(file_path, max_depth, max_nodes)
        return dependencies

    def get_transitive_dependencies_with_paths(
        self,
        file_path: str,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> tuple[set[str], dict[str, list[str]]]:
        """Return transitive dependencies and the shortest import chain leading to each.

        Returns:
            A tuple of (set of dependency file paths, mapping of dependency -> [chain of files]).
        """
        max_depth = MAX_TRAVERSAL_DEPTH if max_depth is None else max_depth
        max_nodes = MAX_VISITED_NODES if max_nodes is None else max_nodes
        start = _normalize_path(file_path)
        visited: set[str] = set()
        paths_to: dict[str, list[str]] = {}
        queue: deque[tuple[str, int, list[str]]] = deque()

        # Initialize with direct dependencies (forward edges)
        for direct in sorted(self.forward.get(start, set())):
            if direct != start:
                queue.append((direct, 1, [start, direct]))

        while queue and len(visited) < max_nodes:
            current, depth, path = queue.popleft()
            if current in visited or current == start:
                continue
            visited.add(current)
            if current not in paths_to:
                paths_to[current] = path

            if depth < max_depth:
                for nxt in sorted(self.forward.get(current, set())):
                    if nxt not in visited and nxt != start and len(visited) + len(queue) < max_nodes:
                        queue.append((nxt, depth + 1, path + [nxt]))

        return visited, paths_to


class _ImportVisitor(ast.NodeVisitor):
    """AST visitor collecting import statements and dynamic import patterns."""

    def __init__(self) -> None:
        self.records: list[ImportRecord] = []
        self.dynamic_warnings: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.records.append(
                ImportRecord(
                    raw_name=alias.name,
                    imported_names=(alias.name,),
                    is_relative=False,
                    level=0,
                    line_number=node.lineno,
                )
            )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        level = node.level or 0
        names = tuple(alias.name for alias in node.names)
        self.records.append(
            ImportRecord(
                raw_name=module,
                imported_names=names,
                is_relative=level > 0,
                level=level,
                line_number=node.lineno,
            )
        )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Detect dynamic module-loading patterns
        if isinstance(node.func, ast.Name):
            if node.func.id in {"__import__", "exec", "eval"}:
                self.dynamic_warnings.append(
                    f"Line {node.lineno}: Dynamic execution call '{node.func.id}()'"
                )
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr == "import_module":
                self.dynamic_warnings.append(
                    f"Line {node.lineno}: Dynamic module import 'import_module()'"
                )
        self.generic_visit(node)


def _is_stdlib_module(top_module: str) -> bool:
    """Determine if a top-level module is part of the Python standard library."""
    if hasattr(sys, "stdlib_module_names"):
        return top_module in sys.stdlib_module_names
    # Fallback list for older Python versions
    return top_module in sys.builtin_module_names


def _resolve_relative_import(
    root: Path,
    source_file: str,
    record: ImportRecord,
) -> list[ResolvedImport]:
    """Resolve a relative import against the project root."""
    root_resolved = root.resolve()
    source_path = root / source_file
    current_dir = source_path.parent

    # Check root escape from level
    steps_up = record.level - 1
    try:
        rel_current = current_dir.resolve().relative_to(root_resolved)
    except (ValueError, OSError):
        return [
            ResolvedImport(
                source_file=source_file,
                module_name=record.raw_name,
                target_file=None,
                classification="ESCAPE_REJECTED",
                detail=f"Source directory {current_dir} escapes project root",
            )
        ]

    if steps_up > len(rel_current.parts):
        return [
            ResolvedImport(
                source_file=source_file,
                module_name=record.raw_name,
                target_file=None,
                classification="ESCAPE_REJECTED",
                detail=f"Relative import level {record.level} escapes project root",
            )
        ]

    base_dir = current_dir
    for _ in range(steps_up):
        base_dir = base_dir.parent

    sub_parts = record.raw_name.split(".") if record.raw_name else []
    target_base = base_dir.joinpath(*sub_parts) if sub_parts else base_dir

    candidates: list[Path] = []
    if sub_parts:
        candidates.append(target_base.with_suffix(".py"))
        candidates.append(target_base / "__init__.py")

    # If from . import foo, foo might be a module or package
    for name in record.imported_names:
        candidates.append(target_base / f"{name}.py")
        candidates.append(target_base / name / "__init__.py")

    results: list[ResolvedImport] = []
    matched = False

    for cand in candidates:
        if cand.is_file():
            try:
                rel = cand.resolve().relative_to(root_resolved)
                results.append(
                    ResolvedImport(
                        source_file=source_file,
                        module_name=record.raw_name,
                        target_file=rel.as_posix(),
                        classification="LOCAL",
                    )
                )
                matched = True
            except (ValueError, OSError):
                results.append(
                    ResolvedImport(
                        source_file=source_file,
                        module_name=record.raw_name,
                        target_file=None,
                        classification="ESCAPE_REJECTED",
                        detail=f"Candidate {cand} escapes project root",
                    )
                )
                matched = True

    if not matched:
        results.append(
            ResolvedImport(
                source_file=source_file,
                module_name=record.raw_name,
                target_file=None,
                classification="UNRESOLVED",
                detail="Relative target not found on filesystem",
            )
        )

    return results


def _resolve_absolute_import(
    root: Path,
    source_file: str,
    record: ImportRecord,
) -> list[ResolvedImport]:
    """Resolve an absolute import against the project root, current file dir, and src/."""
    root_resolved = root.resolve()
    source_path = root / source_file
    current_dir = source_path.parent

    # Candidate search roots within project
    search_roots = [root_resolved, current_dir.resolve()]
    src_dir = root_resolved / "src"
    if src_dir.is_dir():
        search_roots.append(src_dir)

    module_parts = record.raw_name.split(".")
    candidates: list[Path] = []

    for s_root in search_roots:
        try:
            s_root.relative_to(root_resolved)
        except ValueError:
            continue

        # 1. Check imported names as submodules (e.g. from tests import fixtures -> tests/fixtures.py)
        for name in record.imported_names:
            candidates.append(s_root.joinpath(*module_parts, f"{name}.py"))
            candidates.append(s_root.joinpath(*module_parts, name, "__init__.py"))

        # 2. Full module as file or package
        candidates.append(s_root.joinpath(*module_parts).with_suffix(".py"))
        candidates.append(s_root.joinpath(*module_parts, "__init__.py"))

        # 3. Progressive prefixes (e.g. from auth.policy import verify -> auth/policy.py)
        for k in range(len(module_parts) - 1, 0, -1):
            prefix = module_parts[:k]
            candidates.append(s_root.joinpath(*prefix).with_suffix(".py"))
            candidates.append(s_root.joinpath(*prefix, "__init__.py"))

    results: list[ResolvedImport] = []
    matched = False

    for cand in candidates:
        if cand.is_file():
            try:
                rel = cand.resolve().relative_to(root_resolved)
                results.append(
                    ResolvedImport(
                        source_file=source_file,
                        module_name=record.raw_name,
                        target_file=rel.as_posix(),
                        classification="LOCAL",
                    )
                )
                matched = True
                break
            except (ValueError, OSError):
                results.append(
                    ResolvedImport(
                        source_file=source_file,
                        module_name=record.raw_name,
                        target_file=None,
                        classification="ESCAPE_REJECTED",
                        detail=f"Candidate {cand} escapes project root",
                    )
                )
                matched = True
                break

    if not matched:
        top_name = module_parts[0] if module_parts else ""
        if _is_stdlib_module(top_name):
            results.append(
                ResolvedImport(
                    source_file=source_file,
                    module_name=record.raw_name,
                    target_file=None,
                    classification="STDLIB",
                    detail=f"Python standard library module '{top_name}'",
                )
            )
        else:
            # Check if external installed library
            try:
                spec = importlib.util.find_spec(top_name)
                if spec is not None:
                    results.append(
                        ResolvedImport(
                            source_file=source_file,
                            module_name=record.raw_name,
                            target_file=None,
                            classification="EXTERNAL",
                            detail=f"External package '{top_name}'",
                        )
                    )
                else:
                    results.append(
                        ResolvedImport(
                            source_file=source_file,
                            module_name=record.raw_name,
                            target_file=None,
                            classification="UNRESOLVED",
                            detail=f"Module '{record.raw_name}' could not be located",
                        )
                    )
            except (ValueError, AttributeError, ImportError):
                results.append(
                    ResolvedImport(
                        source_file=source_file,
                        module_name=record.raw_name,
                        target_file=None,
                        classification="UNRESOLVED",
                        detail=f"Module '{record.raw_name}' lookup failed",
                    )
                )

    return results


def find_local_python_files(root: Path, excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS) -> list[Path]:
    """Find all candidate Python files under root while respecting exclusions and symlink bounds."""
    root_resolved = root.resolve()
    python_files: list[Path] = []

    for entry in sorted(root_resolved.rglob("*.py")):
        try:
            rel = entry.relative_to(root_resolved)
        except ValueError:
            continue

        # Exclude directories
        if any(part in excluded_dirs for part in rel.parts[:-1]):
            continue

        # Out-of-root symlinks are still returned: build_local_dependency_graph refuses to
        # read them but must RECORD that a file was skipped (a silent skip would look like
        # complete analysis). They are never parsed.
        if entry.is_file() or entry.is_symlink():
            python_files.append(entry)

    return python_files


def build_local_dependency_graph(
    root: Path,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> DependencyGraph:
    """Build the static local Python dependency graph for the configured project root.

    This function is strictly read-only. It parses files into in-memory ASTs,
    detects imports, resolves project-local files, and maps forward and reverse
    dependency edges.
    """
    root_resolved = root.resolve()
    graph = DependencyGraph(root=root_resolved)
    py_files = find_local_python_files(root_resolved, excluded_dirs=excluded_dirs)

    for file_path in py_files:
        try:
            rel_file = file_path.relative_to(root_resolved).as_posix()
        except ValueError:
            continue

        # Symlink check
        if file_path.is_symlink():
            try:
                target = file_path.resolve()
                target.relative_to(root_resolved)
            except (ValueError, OSError):
                graph.uncertainties.append(f"Symlink escapes project root: {rel_file}")
                graph._note_incomplete(rel_file, "UNPARSEABLE", "symlink escapes project root; content not analyzed")
                continue

        # Size check (2 MiB limit)
        try:
            file_stat = file_path.stat()
            if file_stat.st_size > MAX_FILE_SIZE:
                err_msg = f"File exceeds maximum size limit of 2 MiB ({file_stat.st_size} bytes)"
                graph.parse_errors[rel_file] = err_msg
                graph.uncertainties.append(f"{rel_file}: {err_msg}")
                graph._note_incomplete(rel_file, "UNPARSEABLE", err_msg)
                continue
        except OSError as exc:
            err_msg = f"OSError accessing file: {type(exc).__name__}: {exc}"
            graph.parse_errors[rel_file] = err_msg
            graph.uncertainties.append(f"{rel_file}: {err_msg}")
            graph._note_incomplete(rel_file, "UNPARSEABLE", err_msg)
            continue

        # Read and parse AST
        try:
            source_bytes = file_path.read_bytes()
            tree = ast.parse(source_bytes, filename=rel_file)
        except SyntaxError as exc:
            err_msg = f"SyntaxError at line {exc.lineno}: {exc.msg}"
            graph.parse_errors[rel_file] = err_msg
            graph.uncertainties.append(f"{rel_file}: {err_msg}")
            graph._note_incomplete(rel_file, "UNPARSEABLE", err_msg)
            continue
        except UnicodeDecodeError as exc:
            err_msg = f"UnicodeDecodeError: {exc.reason}"
            graph.parse_errors[rel_file] = err_msg
            graph.uncertainties.append(f"{rel_file}: {err_msg}")
            graph._note_incomplete(rel_file, "UNPARSEABLE", err_msg)
            continue
        except OSError as exc:
            err_msg = f"OSError reading file: {type(exc).__name__}: {exc}"
            graph.parse_errors[rel_file] = err_msg
            graph.uncertainties.append(f"{rel_file}: {err_msg}")
            graph._note_incomplete(rel_file, "UNPARSEABLE", err_msg)
            continue

        graph.parsed_files.add(rel_file)

        # Extract import records
        visitor = _ImportVisitor()
        visitor.visit(tree)

        if visitor.dynamic_warnings:
            graph.dynamic_import_warnings[rel_file] = visitor.dynamic_warnings
            for warn in visitor.dynamic_warnings:
                graph.uncertainties.append(f"{rel_file}: {warn}")
                graph._note_incomplete(rel_file, "DYNAMIC_IMPORT", warn)

        # Resolve each import
        file_resolved_imports: list[ResolvedImport] = []
        for record in visitor.records:
            if record.is_relative:
                resolved_list = _resolve_relative_import(root_resolved, rel_file, record)
            else:
                resolved_list = _resolve_absolute_import(root_resolved, rel_file, record)

            for item in resolved_list:
                item = replace(item, imported_names=tuple(record.imported_names))
                file_resolved_imports.append(item)
                if item.classification == "LOCAL" and item.target_file and item.target_file != rel_file:
                    graph.forward.setdefault(rel_file, set()).add(item.target_file)
                    graph.reverse.setdefault(item.target_file, set()).add(rel_file)
                elif item.classification == "ESCAPE_REJECTED":
                    graph.uncertainties.append(
                        f"{rel_file}: Import '{item.module_name}' escapes project root ({item.detail})"
                    )
                elif item.classification == "UNRESOLVED":
                    graph.uncertainties.append(
                        f"{rel_file}: Unresolved import '{item.module_name}' ({item.detail})"
                    )
                    graph._note_incomplete(
                        rel_file, "UNRESOLVED_IMPORT", f"Unresolved import '{item.module_name}'",
                        tuple(t for t in (*item.module_name.split("."), *item.imported_names) if t),
                    )

        graph.imports_by_file[rel_file] = file_resolved_imports

    return graph
