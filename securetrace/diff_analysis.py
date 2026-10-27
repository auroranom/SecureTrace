"""Evidence-based code change and diff assessment for SecureTrace.

This module inspects prospective code changes between original disk content and
proposed content. It provides deterministic, AST-grounded diff analysis that
evaluates how a proposed change interacts with registered security requirements
(such as SEC-D91558F9: "Only appointment owners can cancel").

WHAT THIS IS NOT. This is targeted, name- and shape-based static analysis of Python ASTs.
It does not execute code, resolve dynamic dispatch, follow calls across files, track data
flow, or prove that a requirement is (or is not) satisfied. Specifically it cannot see:
code reached via ``getattr``/``importlib``/``exec``, behaviour supplied by decorators or
metaclasses beyond noticing that they changed, class-method bodies (a changed class is
reported UNCERTAIN, not analysed), reordering that moves a guard after the action it
protects, or authorization implemented under names outside AUTH_FUNCTION_PATTERNS.
When it cannot establish impact it says UNCERTAIN and never downgrades that to LOW.

Three things are deliberately kept separate and must not be conflated:
  * requirement severity - registered with the requirement, not computed here;
  * change risk / classification - this module's assessment of one proposed edit;
  * enforcement - whether review is required is decided by requirement linkage in
    approval.evaluate_proposal, NOT by this classification. A COMMENT_ONLY edit to a
    protected file is still reviewed; this module only informs the reviewer.
"""
from __future__ import annotations

import ast
import copy
from dataclasses import dataclass, field
import difflib
from pathlib import Path
from typing import Any


AUTH_FUNCTION_PATTERNS = (
    "can_cancel_appointment",
    "can_cancel",
    "can_",
    "is_authorized",
    "check_permission",
    "has_access",
    "authorize",
    "authenticate",
    "verify_ownership",
    "check_ownership",
)


@dataclass
class DiffAssessment:
    """Deterministic, evidence-based assessment of a prospective code change."""
    classification: str  # "COMMENT_ONLY", "UNRELATED_LOGIC", "MODIFIES_AUTH_LOGIC", "REMOVES_OR_WEAKENS_CHECK", "UNCERTAIN"
    assessed_risk: str   # "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNCERTAIN"
    summary: str
    evidence: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)
    recommended_tests: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "assessed_risk": self.assessed_risk,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "uncertainties": list(self.uncertainties),
            "recommended_tests": list(self.recommended_tests),
            "details": dict(self.details),
        }


def _strip_docstrings(tree: ast.AST) -> ast.AST:
    """Return a deep copy of the AST with all docstrings removed."""
    tree_copy = copy.deepcopy(tree)
    for node in ast.walk(tree_copy):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body = node.body[1:]
    return tree_copy


def _ast_dump_clean(node: ast.AST) -> str:
    """Dump AST without line numbers or source column attributes for structural comparison."""
    return ast.dump(node, include_attributes=False)


def _ast_structurally_identical(tree1: ast.AST, tree2: ast.AST) -> bool:
    """Compare two AST trees for identical executable structure (ignoring docstrings and comments)."""
    clean1 = _strip_docstrings(tree1)
    clean2 = _strip_docstrings(tree2)
    return _ast_dump_clean(clean1) == _ast_dump_clean(clean2)


def _has_dynamic_constructs(tree: ast.AST) -> list[str]:
    """Identify dynamic metaprogramming constructs that prevent confident static analysis."""
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id in ("eval", "exec", "__import__"):
                    found.append(f"Direct call to '{node.func.id}()'")
                elif node.func.id in ("globals", "locals") and any(
                    isinstance(p, (ast.Subscript, ast.Attribute)) for p in ast.walk(node)
                ):
                    found.append(f"Dynamic namespace lookup via '{node.func.id}()'")
            elif isinstance(node.func, ast.Attribute) and node.func.attr in ("setattr", "delattr"):
                found.append(f"Dynamic attribute modification via '{node.func.attr}()'")
    return sorted(set(found))


def _count_dynamic(tree: ast.AST) -> int:
    """Number of dynamic-construct call sites (a second ``eval`` is a change even if one existed)."""
    return sum(
        1 for node in ast.walk(tree)
        if isinstance(node, ast.Call) and (
            (isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec", "__import__"))
            or (isinstance(node.func, ast.Attribute) and node.func.attr in ("setattr", "delattr"))
        )
    )


def _is_auth_name(name: str) -> bool:
    return any(name == pat or name.startswith(pat) for pat in AUTH_FUNCTION_PATTERNS)


def _callee_closure(start: ast.AST, fns: dict[str, Any]) -> set[str]:
    """Names of same-module functions reachable (transitively, by simple name) from ``start``."""
    seen: set[str] = set()
    todo = [c for c in _extract_calls(start) if c in fns]
    while todo:
        name = sorted(todo)[0]
        todo.remove(name)
        if name in seen:
            continue
        seen.add(name)
        todo.extend(c for c in _extract_calls(fns[name]) if c in fns and c not in seen)
    return seen


def _count_ops(fn: ast.AST, kinds: tuple[type, ...]) -> int:
    return sum(1 for n in ast.walk(fn) if isinstance(n, ast.Compare) for op in n.ops if isinstance(op, kinds))


def _boolop_stats(fn: ast.AST) -> tuple[int, int]:
    """(number of operands joined by AND, number of OR expressions)."""
    ands = sum(len(n.values) for n in ast.walk(fn) if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.And))
    ors = sum(1 for n in ast.walk(fn) if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.Or))
    return ands, ors


def _count_return_true(fn: ast.AST) -> int:
    return sum(1 for n in ast.walk(fn) if isinstance(n, ast.Return)
               and isinstance(n.value, ast.Constant) and n.value.value is True)


def _module_rebinds(other_stmts: list[ast.stmt], names: set[str]) -> list[str]:
    """Module-level statements that rebind one of ``names`` (assignment or import alias)."""
    hit: set[str] = set()
    for stmt in other_stmts:
        targets: list[ast.AST] = []
        if isinstance(stmt, ast.Assign):
            targets = list(stmt.targets)
        elif isinstance(stmt, (ast.AnnAssign, ast.AugAssign)):
            targets = [stmt.target]
        for t in targets:
            for n in ast.walk(t):
                if isinstance(n, ast.Name) and n.id in names:
                    hit.add(n.id)
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                bound = (alias.asname or alias.name).split(".")[0]
                if bound in names:
                    hit.add(bound)
    return sorted(hit)


_RISK_RANK = {"LOW": 0, "UNCERTAIN": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_CLASS_RANK = {"COMMENT_ONLY": 0, "UNRELATED_LOGIC": 1, "UNCERTAIN": 2, "MODIFIES_AUTH_LOGIC": 3, "REMOVES_OR_WEAKENS_CHECK": 4}


def _extract_calls(node: ast.AST) -> set[str]:
    """Extract names of functions called inside an AST node."""
    calls: set[str] = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            if isinstance(n.func, ast.Name):
                calls.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                calls.add(n.func.attr)
    return calls


def _extract_top_level_items(tree: ast.Module) -> tuple[
    dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    dict[str, ast.ClassDef],
    list[ast.stmt],
]:
    """Separate top-level functions, classes, and other module statements (e.g. imports, assignments)."""
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    classes: dict[str, ast.ClassDef] = {}
    other_stmts: list[ast.stmt] = []

    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[stmt.name] = stmt
        elif isinstance(stmt, ast.ClassDef):
            classes[stmt.name] = stmt
        else:
            other_stmts.append(stmt)

    return functions, classes, other_stmts


def _is_ownership_comparison(comp: ast.Compare) -> bool:
    """Check if an AST comparison looks like an ownership check (e.g. actor == owner)."""
    names: set[str] = set()
    for n in ast.walk(comp):
        if isinstance(n, ast.Name):
            names.add(n.id.lower())
    has_actor = any("actor" in name or "user" in name for name in names)
    has_owner = any("owner" in name for name in names)
    return has_actor and has_owner


def _analyze_can_cancel_function(
    orig_fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
    prop_fn: ast.FunctionDef | ast.AsyncFunctionDef | None,
) -> tuple[str, str, list[str]]:
    """Specific analysis for appointment ownership check (e.g. can_cancel_appointment)."""
    if prop_fn is None:
        return (
            "REMOVES_OR_WEAKENS_CHECK",
            "CRITICAL",
            ["The entire authorization control function was deleted from the module."],
        )

    if orig_fn is None:
        return (
            "MODIFIES_AUTH_LOGIC",
            "HIGH",
            ["A new authorization control function was added."],
        )

    orig_clean = _strip_docstrings(orig_fn)
    prop_clean = _strip_docstrings(prop_fn)

    if _ast_dump_clean(orig_clean) == _ast_dump_clean(prop_clean):
        return (
            "COMMENT_ONLY",
            "LOW",
            ["The executable statements of the authorization function are unchanged."],
        )

    evidence: list[str] = []

    # Unconditional approval: judged RELATIVE to the original so a function that already
    # had a legitimate `return True` branch is not flagged merely for being edited.
    if _count_return_true(prop_fn) > _count_return_true(orig_fn):
        return (
            "REMOVES_OR_WEAKENS_CHECK",
            "CRITICAL",
            ["A new unconditional 'return True' path was introduced; the authorization check can be bypassed."],
        )

    orig_eq = _count_ops(orig_fn, (ast.Eq, ast.Is))
    prop_eq = _count_ops(prop_fn, (ast.Eq, ast.Is))
    orig_ne = _count_ops(orig_fn, (ast.NotEq, ast.IsNot))
    prop_ne = _count_ops(prop_fn, (ast.NotEq, ast.IsNot))

    if prop_eq < orig_eq:
        if prop_ne > orig_ne:
            return (
                "REMOVES_OR_WEAKENS_CHECK",
                "CRITICAL",
                ["The ownership comparison was negated (== replaced by !=): the check now permits everyone except the owner."],
            )
        return (
            "REMOVES_OR_WEAKENS_CHECK",
            "CRITICAL",
            [
                "The ownership equality comparison (checking whether the actor is the appointment owner) was removed.",
                "The function returns without verifying that actor_id matches appointment_owner_id.",
            ],
        )

    orig_ands, orig_ors = _boolop_stats(orig_fn)
    prop_ands, prop_ors = _boolop_stats(prop_fn)
    if prop_ors > orig_ors:
        return (
            "REMOVES_OR_WEAKENS_CHECK",
            "CRITICAL",
            [
                "The conditional operator was changed from AND to OR, allowing unauthorized cancellation without ownership."
                if prop_ands < orig_ands else
                "An OR alternative was introduced into the authorization condition; any one branch alone now suffices.",
            ],
        )

    orig_bool_calls = sum(1 for n in ast.walk(orig_fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "bool")
    prop_bool_calls = sum(1 for n in ast.walk(prop_fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "bool")
    if prop_ands < orig_ands or prop_bool_calls < orig_bool_calls:
        # Kept at MODIFIES_AUTH_LOGIC/HIGH (existing, tested contract): the ownership comparison
        # itself survives, so this is not classed as removing the check, but the evidence says
        # plainly that identity validation was removed.
        evidence.append(
            "Actor identity validation (e.g. bool(actor_id)) was removed; an absent actor may now match an absent owner."
        )

    if ast.dump(orig_fn.args) != ast.dump(prop_fn.args):
        evidence.append(
            f"Function parameter list or defaults changed from ({ast.unparse(orig_fn.args)}) to ({ast.unparse(prop_fn.args)}), "
            "altering how actor identity or owner is received."
        )
    if [ast.dump(d) for d in orig_fn.decorator_list] != [ast.dump(d) for d in prop_fn.decorator_list]:
        evidence.append(
            "Decorators on the authorization function were modified; decorators can change results "
            "(e.g. caching) in ways not visible from the function body."
        )
    if prop_bool_calls > orig_bool_calls:
        evidence.append("Actor identity presence validation (e.g. bool(actor_id)) was modified.")

    orig_comps = sorted(_ast_dump_clean(n) for n in ast.walk(orig_fn) if isinstance(n, ast.Compare))
    prop_comps = sorted(_ast_dump_clean(n) for n in ast.walk(prop_fn) if isinstance(n, ast.Compare))
    if orig_comps != prop_comps:
        evidence.append("The ownership comparison expression was altered.")

    if not evidence:
        evidence.append("Internal logic or expressions inside the authorization control function were modified.")

    return ("MODIFIES_AUTH_LOGIC", "HIGH", evidence)


def _find_recommended_tests(
    root: Path | None,
    affected_requirements: list[dict[str, Any]],
    file_path: str,
) -> list[str]:
    """Find verification tests linked to affected requirements or relevant to the modified file."""
    tests: list[str] = []

    if root is not None:
        try:
            from .ledger import list_requirement_tests
            for req in affected_requirements:
                req_id = req.get("id") or req.get("requirement_id")
                if req_id:
                    mapped = list_requirement_tests(root, req_id)
                    for item in mapped:
                        test_file = item.get("test_file")
                        test_id = item.get("test_id")
                        if test_file and test_id:
                            tests.append(f"{test_file}::{test_id}")
                        elif test_file:
                            tests.append(test_file)
        except Exception:
            pass

    # Common demo tests fallback if not found in db
    if not tests:
        if "app.py" in file_path or any("D91558F9" in str(r.get("id", "")) for r in affected_requirements):
            tests.append("examples/authorization_demo/tests/test_authorization.py::test_other_user_cannot_cancel_appointment")
            tests.append("examples/authorization_demo/tests/test_authorization.py::test_owner_can_cancel_appointment")

    return sorted(set(tests))


def assess_proposed_diff(
    original_content: str,
    proposed_content: str,
    file_path: str,
    affected_requirements: list[dict[str, Any]],
    root: Path | None = None,
) -> DiffAssessment:
    """Evaluate a prospective file modification against registered requirements using diff evidence."""
    recommended_tests = _find_recommended_tests(root, affected_requirements, file_path)

    # 1. Non-Python files
    if not file_path.endswith(".py"):
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="UNCERTAIN",
            summary=f"Proposed changes to non-Python file `{file_path}` cannot be verified by structural analysis.",
            evidence=[f"File `{file_path}` is not a Python source file; semantic syntax analysis is unsupported."],
            uncertainties=["Semantic effects of non-Python file modifications cannot be established statically."],
            recommended_tests=recommended_tests,
            details={"file_path": file_path, "file_type": "non_python"},
        )

    # 2. Parse original and proposed AST
    orig_parse_err: str | None = None
    prop_parse_err: str | None = None

    try:
        orig_tree = ast.parse(original_content)
    except SyntaxError as exc:
        orig_parse_err = f"Original file has syntax error: {exc}"
        orig_tree = None

    try:
        prop_tree = ast.parse(proposed_content)
    except SyntaxError as exc:
        prop_parse_err = f"Proposed change introduces a syntax error: {exc}"
        prop_tree = None

    if orig_parse_err or prop_parse_err:
        errors = [e for e in (orig_parse_err, prop_parse_err) if e]
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="UNCERTAIN",
            summary=f"Syntax error encountered while analyzing `{file_path}`; code structure cannot be established safely.",
            evidence=errors,
            uncertainties=["Malformed or syntactically invalid Python prevents safe structural analysis."],
            recommended_tests=recommended_tests,
            details={"syntax_errors": errors},
        )

    assert orig_tree is not None and prop_tree is not None

    # 3. Check for dynamic constructs newly introduced
    dynamic_calls = _has_dynamic_constructs(prop_tree)
    if dynamic_calls and _count_dynamic(prop_tree) > _count_dynamic(orig_tree):
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="HIGH",
            summary=f"Dynamic metaprogramming constructs detected in `{file_path}`; static analysis cannot guarantee safety.",
            evidence=[f"Proposed change introduces dynamic constructs: {', '.join(dynamic_calls)}."],
            uncertainties=["Dynamic calls bypass static analysis and may alter runtime execution unpredictably."],
            recommended_tests=recommended_tests,
            details={"dynamic_constructs": dynamic_calls},
        )

    # 4. Check for COMMENT_ONLY
    if _ast_structurally_identical(orig_tree, prop_tree):
        return DiffAssessment(
            classification="COMMENT_ONLY",
            assessed_risk="LOW",
            summary="Proposed change consists solely of comments, docstrings, or formatting; executable application logic is completely untouched.",
            evidence=[
                "Structural syntax analysis confirms all executable code statements, control flow, and expressions are identical.",
                "Only non-executing comments, docstrings, or whitespace were added, modified, or removed.",
            ],
            uncertainties=[
                "Static analysis confirms executable code is identical, but modified comments or docstrings could still mislead developers or AI tools reading the code.",
            ],
            recommended_tests=recommended_tests,
            details={"identical_executable_ast": True},
        )

    # 5. Extract top-level definitions
    orig_fns, orig_classes, orig_other = _extract_top_level_items(orig_tree)
    prop_fns, prop_classes, prop_other = _extract_top_level_items(prop_tree)

    # Every recognised authorization function (sorted: set order must never choose the target).
    auth_names = sorted(n for n in set(orig_fns) | set(prop_fns) if _is_auth_name(n))
    orig_auth = {n for n in auth_names if n in orig_fns}

    def _changed(name: str, a: dict[str, Any], b: dict[str, Any]) -> bool:
        x, y = a.get(name), b.get(name)
        return (x is None) != (y is None) or (x is not None and not _ast_structurally_identical(x, y))

    # 5a. Authorization function(s) changed: report the most severe finding.
    findings: list[tuple[str, str, list[str], str]] = []
    for name in auth_names:
        if _changed(name, orig_fns, prop_fns):
            cls_, risk_, ev_ = _analyze_can_cancel_function(orig_fns.get(name), prop_fns.get(name))
            findings.append((cls_, risk_, ev_, name))
    if findings:
        cls_, risk_, ev_, name = max(findings, key=lambda f: (_RISK_RANK[f[1]], _CLASS_RANK[f[0]], f[3]))
        return DiffAssessment(
            classification=cls_,
            assessed_risk=risk_,
            summary=f"Authorization logic in `{name}()` was modified.",
            evidence=ev_,
            uncertainties=[
                "Static analysis examines direct code syntax and structure; runtime callers and environmental dependencies should be validated via automated tests."
            ],
            recommended_tests=recommended_tests,
            details={"target_function": name, "changed_authorization_functions": [f[3] for f in sorted(findings, key=lambda f: f[3])]},
        )

    # 5b. A module-level statement rebinding an authorization function shadows the checked definition.
    rebound = _module_rebinds(prop_other, orig_auth) if orig_auth else []
    if rebound and _module_rebinds(orig_other, orig_auth) != rebound:
        return DiffAssessment(
            classification="REMOVES_OR_WEAKENS_CHECK",
            assessed_risk="CRITICAL",
            summary=f"Authorization function(s) `{', '.join(rebound)}` are rebound by a module-level statement in `{file_path}`.",
            evidence=[
                f"The name(s) {', '.join(rebound)} were rebound at module level (assignment or import), so callers use the "
                "new object instead of the reviewed definition.",
            ],
            uncertainties=["The replacement's behaviour cannot be established statically."],
            recommended_tests=recommended_tests,
            details={"rebound_names": rebound},
        )

    # 6. Check module-level statement changes (imports, globals)
    # Changes outside functions cannot be assumed unrelated if they touch module-level variables or imports
    orig_other_dump = _ast_dump_clean(ast.Module(body=orig_other, type_ignores=[]))
    prop_other_dump = _ast_dump_clean(ast.Module(body=prop_other, type_ignores=[]))
    module_level_changed = orig_other_dump != prop_other_dump

    if module_level_changed:
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="HIGH",
            summary=f"Module-level statements (such as imports or global variables) were modified in `{file_path}`.",
            evidence=[
                "Top-level module code was changed outside isolated function boundaries.",
                "Module-level changes can alter shared runtime state, imported symbols, or configuration consumed by authorization controls.",
            ],
            uncertainties=[
                "The indirect side effects of modified module-level statements on protected functions cannot be proven safe without execution."
            ],
            recommended_tests=recommended_tests,
            details={"module_level_changed": True},
        )

    all_fn_names = sorted(set(orig_fns) | set(prop_fns))
    changed_fns = [n for n in all_fn_names if _changed(n, orig_fns, prop_fns)]

    # 7a. Helpers the authorization functions rely on, directly or through other same-module helpers.
    relied_on: set[str] = set()
    for name in orig_auth:
        relied_on |= _callee_closure(orig_fns[name], orig_fns)
    for name in (n for n in auth_names if n in prop_fns):
        relied_on |= _callee_closure(prop_fns[name], prop_fns)
    called_changed_fns = [f for f in changed_fns if f in relied_on]
    if called_changed_fns:
        anchor = auth_names[0] if auth_names else "the protected function"
        return DiffAssessment(
            classification="MODIFIES_AUTH_LOGIC",
            assessed_risk="HIGH",
            summary=f"Helper function(s) `{', '.join(called_changed_fns)}` relied on by `{anchor}()` were modified.",
            evidence=[
                f"Authorization function(s) {', '.join('`'+n+'()`' for n in auth_names)} directly or transitively rely on "
                f"`{', '.join(called_changed_fns)}` (same-module call graph).",
                "Modifying these helper functions alters the behavior of the protected authorization flow.",
            ],
            uncertainties=[
                "Call tree analysis confirms dependencies; impact on security assertions requires executing verification tests."
            ],
            recommended_tests=recommended_tests,
            details={"changed_helpers": called_changed_fns},
        )

    # 7b. Functions that CALL an authorization function (guards). Dropping the call removes the check
    #     from that code path even though the check function itself is untouched.
    guarded_orig = sorted(n for n in orig_fns if n not in auth_names and _extract_calls(orig_fns[n]) & set(orig_auth))
    for name in (n for n in changed_fns if n in guarded_orig and n in prop_fns):
        if not (_extract_calls(prop_fns[name]) & set(auth_names)):
            return DiffAssessment(
                classification="REMOVES_OR_WEAKENS_CHECK",
                assessed_risk="CRITICAL",
                summary=f"`{name}()` no longer calls the authorization check it previously relied on.",
                evidence=[
                    f"`{name}()` previously called {', '.join('`'+n+'()`' for n in sorted(_extract_calls(orig_fns[name]) & set(orig_auth)))} "
                    "and no longer calls any authorization function: this code path is now unguarded.",
                ],
                uncertainties=["The check function itself is unchanged; the weakening is at its call site."],
                recommended_tests=recommended_tests,
                details={"unguarded_function": name},
            )
    changed_guarded = [n for n in changed_fns if n in guarded_orig and n in prop_fns]
    new_unguarded = [
        n for n in changed_fns
        if n not in orig_fns and n in prop_fns and guarded_orig and not (_extract_calls(prop_fns[n]) & set(auth_names))
    ]
    if changed_guarded or new_unguarded:
        evidence = []
        if changed_guarded:
            evidence.append(
                f"Guarded function(s) {', '.join('`'+n+'()`' for n in changed_guarded)} were modified; the guard call is still present "
                "but whether it still dominates the protected operation cannot be established statically."
            )
        if new_unguarded:
            evidence.append(
                f"New function(s) {', '.join('`'+n+'()`' for n in new_unguarded)} are not guarded by an authorization call, while existing "
                f"function(s) {', '.join('`'+n+'()`' for n in guarded_orig)} are; an alternate path around the check cannot be ruled out."
            )
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="MEDIUM",
            summary=f"Callers of the authorization check were changed or added in `{file_path}`; bypass cannot be ruled out.",
            evidence=evidence,
            uncertainties=["Control-flow dominance and reachability are not analysed."],
            recommended_tests=recommended_tests,
            details={"changed_guarded_functions": changed_guarded, "new_unguarded_functions": new_unguarded},
        )

    # 7c. Classes: method bodies are not analysed, so a changed class is never "unrelated".
    all_class_names = sorted(set(orig_classes) | set(prop_classes))
    changed_classes = [n for n in all_class_names if _changed(n, orig_classes, prop_classes)]
    if changed_classes:
        return DiffAssessment(
            classification="UNCERTAIN",
            assessed_risk="MEDIUM",
            summary=f"Class definition(s) `{', '.join(changed_classes)}` changed in `{file_path}`; method bodies are not analysed.",
            evidence=[f"The class(es) {', '.join(changed_classes)} were added, removed, or modified; methods can implement or bypass authorization."],
            uncertainties=["Class and method semantics are outside this analyzer's scope."],
            recommended_tests=recommended_tests,
            details={"changed_classes": changed_classes},
        )

    # 7d. Only plain functions changed. "Unrelated" may be claimed only if a protected function was
    #     actually identified and left untouched; otherwise we simply do not know what is protected.
    if changed_fns:
        if not auth_names:
            return DiffAssessment(
                classification="UNCERTAIN",
                assessed_risk="MEDIUM",
                summary=f"Function(s) `{', '.join(changed_fns)}` changed in `{file_path}`, which contains no recognisable authorization function.",
                evidence=[
                    "No function matching a known authorization naming pattern was found, so SecureTrace cannot establish "
                    "that the changed code is unrelated to the registered requirement.",
                ],
                uncertainties=["Which code implements the requirement is unknown to this analyzer."],
                recommended_tests=recommended_tests,
                details={"changed_functions": changed_fns},
            )
        anchor = ", ".join(auth_names)
        return DiffAssessment(
            classification="UNRELATED_LOGIC",
            assessed_risk="LOW",
            summary=f"Changes in `{file_path}` are strictly isolated to function(s) `{', '.join(changed_fns)}`; authorization control `{anchor}` is unchanged.",
            evidence=[
                f"The protected authorization control `{anchor}` is structurally identical to the original.",
                f"Only separate, uncalled function(s) ({', '.join(changed_fns)}) were modified.",
                "No module-level variables, imports, or shared statements were altered.",
            ],
            uncertainties=[
                "Static analysis confirms call-graph separation, but runtime side effects or shared global state cannot be 100% ruled out."
            ],
            recommended_tests=recommended_tests,
            details={"unrelated_functions": changed_fns},
        )

    # Fallback if other constructs changed
    return DiffAssessment(
        classification="UNCERTAIN",
        assessed_risk="MEDIUM",
        summary=f"Structural modifications detected in `{file_path}` that cannot be verified as strictly unrelated.",
        evidence=["Modifications exist outside standard function definitions."],
        uncertainties=["Complex structural changes require full test suite execution for confirmation."],
        recommended_tests=recommended_tests,
    )
