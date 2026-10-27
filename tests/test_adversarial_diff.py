"""Phase 3: adversarial authorization-change scenarios.

Each scenario asserts, end to end on an isolated project:
  classification, assessed risk, evidence, recommended tests, review required
  (assessment decision) AND actual enforcement by the pre-action hook.

Static-analysis limits (read before trusting a green run): the analyzer is a
targeted AST heuristic. It does not execute code, follow dynamic dispatch, or
prove a requirement is satisfied. UNCERTAIN means "could not establish", and
is never downgraded to a low-risk label. Review enforcement does NOT depend on
the classification at all: any change touching a requirement-linked file (or
its known dependents) forces review; the classification only informs the reviewer.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from securetrace.approval import evaluate_proposal
from securetrace.db import migrate_mappings
from securetrace.hooks import handle_pre_tool_use
from securetrace.ledger import add_requirement, map_requirement_test

ORIG = '''\
"""Appointments."""
import os

LIMIT = 3


def can_cancel_appointment(actor_id, appointment_owner_id):
    return bool(actor_id) and actor_id == appointment_owner_id


def cancel_appointment(appointments, appointment_id, actor_id):
    appt = appointments[appointment_id]
    if not can_cancel_appointment(actor_id, appt["owner"]):
        raise PermissionError("not owner")
    del appointments[appointment_id]
    return True


def list_appointments(appointments):
    return sorted(appointments)
'''

HELPER_ORIG = ORIG.replace(
    "    return bool(actor_id) and actor_id == appointment_owner_id\n",
    "    return bool(actor_id) and _same(actor_id, appointment_owner_id)\n",
).replace(
    "def can_cancel_appointment",
    "def _norm(x):\n    return str(x)\n\n\ndef _same(a, b):\n    return _norm(a) == _norm(b)\n\n\ndef can_cancel_appointment",
)

GATE = "tests/test_auth.py::test_owner_only"


def _make(tmp_path: Path, source: str = ORIG, extra: dict[str, str] | None = None) -> Path:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_auth.py").write_text("def test_owner_only():\n    assert True\n", encoding="utf-8")
    for name, text in (extra or {}).items():
        (tmp_path / name).write_text(text, encoding="utf-8")
    migrate_mappings(tmp_path)
    req = add_requirement(tmp_path, "Only owners cancel", "Owner check", category="authorization",
                          severity="critical", file_paths=["app.py"])["id"]
    map_requirement_test(tmp_path, req, "tests/test_auth.py", "test_owner_only")
    return tmp_path


def _hook(root: Path, rel: str, content: str) -> dict:
    return handle_pre_tool_use({
        "toolCall": {"name": "write_to_file", "args": {"TargetFile": rel, "CodeContent": content}},
        "workspacePaths": [str(root)],
    })


def _check(root, rel, content, cls, risk, evidence_substr):
    p = evaluate_proposal(root, rel, content=content)
    assert p.diff_classification == cls, (p.diff_classification, p.diff_evidence)
    assert p.assessed_risk == risk
    assert any(evidence_substr.lower() in e.lower() for e in p.diff_evidence), p.diff_evidence
    assert GATE in p.recommended_tests
    assert p.decision == "FORCE_ASK"                       # review required
    assert _hook(root, rel, content)["decision"] == "force_ask"   # and actually enforced
    return p


CASES_ON_ORIG = [
    ("01_comment_added", ORIG.replace("LIMIT = 3", "LIMIT = 3  # note"), "COMMENT_ONLY", "LOW", "identical"),
    ("01b_comment_removed", ORIG.replace('"""Appointments."""\n', ""), "COMMENT_ONLY", "LOW", "identical"),
    ("02_harmless_independent_function", ORIG.replace("sorted(appointments)", "sorted(appointments, reverse=True)"),
     "UNRELATED_LOGIC", "LOW", "separate"),
    ("03_reverse_ownership_comparison", ORIG.replace("actor_id == appointment_owner_id", "actor_id != appointment_owner_id"),
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "negat"),
    ("04_remove_actor_validation", ORIG.replace("bool(actor_id) and ", ""),
     "MODIFIES_AUTH_LOGIC", "HIGH", "identity validation"),   # existing contract: HIGH, evidence says removed
    ("05_unconditional_true", ORIG.replace("return bool(actor_id) and actor_id == appointment_owner_id", "return True"),
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "return True"),
    ("06_and_to_or", ORIG.replace("bool(actor_id) and actor_id", "bool(actor_id) or actor_id"),
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "AND to OR"),
    ("07_comparison_to_unrelated_expression", ORIG.replace("actor_id == appointment_owner_id", 'actor_id == "admin"'),
     "MODIFIES_AUTH_LOGIC", "HIGH", "comparison"),
    ("08_signature_change", ORIG.replace("def can_cancel_appointment(actor_id, appointment_owner_id)", "def can_cancel_appointment(actor_id, appointment_owner_id, force=False)"),
     "MODIFIES_AUTH_LOGIC", "HIGH", "parameter"),
    ("08b_default_value_change", ORIG.replace("def can_cancel_appointment(actor_id, appointment_owner_id)", "def can_cancel_appointment(actor_id=None, appointment_owner_id=None)"),
     "MODIFIES_AUTH_LOGIC", "HIGH", "parameter"),
    ("11_module_state", ORIG.replace("LIMIT = 3", "LIMIT = 3\nADMINS = ['root']"), "UNCERTAIN", "HIGH", "module"),
    ("12_dynamic_execution", ORIG.replace("    return sorted(appointments)", "    eval('1')\n    return sorted(appointments)"),
     "UNCERTAIN", "HIGH", "eval"),
    ("12b_second_dynamic_call_when_one_exists", None, "UNCERTAIN", "HIGH", "eval"),
    ("13_malformed_python", ORIG + "\ndef broken(:\n", "UNCERTAIN", "UNCERTAIN", "syntax"),
    ("15_decorator_changes_runtime_behaviour", ORIG.replace("def can_cancel_appointment", "@functools.lru_cache\ndef can_cancel_appointment"),
     "MODIFIES_AUTH_LOGIC", "HIGH", "modified"),
    ("15b_rebind_auth_function", ORIG + "\ncan_cancel_appointment = lambda a, b: True\n",
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "rebound"),
    ("16_import_change", ORIG.replace("import os", "import os\nfrom shim import patch"), "UNCERTAIN", "HIGH", "module"),
    ("17_constant_change", ORIG.replace("LIMIT = 3", "LIMIT = 300"), "UNCERTAIN", "HIGH", "module"),
    ("18a_alternate_path_inside_check", ORIG.replace("    return bool(actor_id) and", '    if actor_id == "admin":\n        return True\n    return bool(actor_id) and'),
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "return True"),
    ("18b_new_unguarded_function", ORIG + "\n\ndef force_cancel(appointments, appointment_id):\n    del appointments[appointment_id]\n",
     "UNCERTAIN", "MEDIUM", "not guarded"),
    ("18c_guard_call_removed_from_caller", ORIG.replace('    if not can_cancel_appointment(actor_id, appt["owner"]):\n        raise PermissionError("not owner")\n', ""),
     "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "no longer calls"),
    ("18d_guarded_caller_modified_guard_kept", ORIG.replace("    return True\n\n\ndef list", "    return 1\n\n\ndef list"),
     "UNCERTAIN", "MEDIUM", "guard"),
    ("19_class_change_alongside_function_change", ORIG + "\n\nclass Booking:\n    def cancel(self):\n        return True\n",
     "UNCERTAIN", "MEDIUM", "class"),
]


@pytest.mark.parametrize("name,content,cls,risk,ev", CASES_ON_ORIG, ids=[c[0] for c in CASES_ON_ORIG])
def test_adversarial_scenarios(tmp_path, name, content, cls, risk, ev):
    root = _make(tmp_path, ORIG if name != "12b_second_dynamic_call_when_one_exists" else ORIG + "\n\ndef _d():\n    eval('1')\n")
    if content is None:
        content = ORIG + "\n\ndef _d():\n    eval('1')\n    eval('2')\n"
    _check(root, "app.py", content, cls, risk, ev)


def test_09_modified_called_helper_and_transitive_helper(tmp_path):
    root = _make(tmp_path, HELPER_ORIG)
    p = _check(root, "app.py", HELPER_ORIG.replace("return _norm(a) == _norm(b)", "return True"),
               "MODIFIES_AUTH_LOGIC", "HIGH", "_same")
    assert p.affected_requirements
    # Helper two calls away from the protected function (can_cancel -> _same -> _norm).
    _check(root, "app.py", HELPER_ORIG.replace("return str(x)", "return 'x'"),
           "MODIFIES_AUTH_LOGIC", "HIGH", "_norm")


def test_10_imported_authorization_helper_in_another_file(tmp_path):
    helper = "def check_permission(actor, owner):\n    return actor == owner\n"
    root = _make(tmp_path, "import authz\n\n" + ORIG, extra={"authz.py": helper})
    p = _check(root, "authz.py", helper.replace("actor == owner", "True"),
               "REMOVES_OR_WEAKENS_CHECK", "CRITICAL", "return True")
    assert p.affected_requirements and p.affected_requirements[0]["dependency_chains"]
    # A dependency whose changed function is not recognisably authorization: unknown, never "unrelated".
    helper2 = "def load_roles():\n    return []\n"
    second = tmp_path / "second"
    second.mkdir()
    root2 = _make(second, "import authz\n\n" + ORIG, extra={"authz.py": helper2})
    _check(root2, "authz.py", helper2.replace("[]", "['admin']"), "UNCERTAIN", "MEDIUM", "cannot")


def test_14_non_python_protected_file(tmp_path):
    root = _make(tmp_path)
    req = add_requirement(root, "Policy file", "Config", category="authorization", severity="high", file_paths=["policy.yaml"])
    (root / "policy.yaml").write_text("allow: owner\n", encoding="utf-8")
    p = evaluate_proposal(root, "policy.yaml", content="allow: everyone\n")
    assert (p.diff_classification, p.assessed_risk) == ("UNCERTAIN", "UNCERTAIN")
    assert p.decision == "FORCE_ASK"
    assert _hook(root, "policy.yaml", "allow: everyone\n")["decision"] == "force_ask"


def test_unrecognised_protected_logic_is_never_called_unrelated(tmp_path):
    """A linked file with no recognisable authorization function: changed code is UNCERTAIN, not LOW."""
    src = "def format_name(x):\n    return str(x)\n\n\ndef other():\n    return 1\n"
    root = _make(tmp_path, src)
    p = evaluate_proposal(root, "app.py", content=src.replace("return 1", "return 2"))
    assert p.diff_classification == "UNCERTAIN" and p.assessed_risk != "LOW"
    assert _hook(root, "app.py", src.replace("return 1", "return 2"))["decision"] == "force_ask"


def test_changed_auth_function_not_first_pattern_match_is_not_missed(tmp_path):
    """Only is_authorized changes while an unchanged can_* exists: previously reported UNRELATED/LOW."""
    src = "def can_view(a):\n    return a\n\n\ndef is_authorized(a, b):\n    return a == b\n"
    root = _make(tmp_path, src)
    p = evaluate_proposal(root, "app.py", content=src.replace("return a == b", "return True"))
    assert (p.diff_classification, p.assessed_risk) == ("REMOVES_OR_WEAKENS_CHECK", "CRITICAL")


def test_classification_is_deterministic_across_hash_seeds(tmp_path):
    """Target selection must not depend on set ordering (PYTHONHASHSEED)."""
    import subprocess, sys, json
    root = _make(tmp_path, "def can_a(x):\n    return x\n\n\ndef can_b(x):\n    return x\n")
    code = (
        "import json,sys;from pathlib import Path;from securetrace.diff_analysis import assess_proposed_diff as a;"
        "o=Path(sys.argv[1]).read_text();p=o.replace('def can_b(x):\\n    return x','def can_b(x):\\n    return True');"
        "r=a(o,p,'app.py',[]);print(json.dumps([r.classification,r.assessed_risk,r.details]))"
    )
    outs = set()
    for seed in ("1", "2", "3", "4"):
        env = {**__import__("os").environ, "PYTHONHASHSEED": seed}
        outs.add(subprocess.run([sys.executable, "-c", code, str(root / "app.py")], capture_output=True, text=True, env=env).stdout)
    assert len(outs) == 1, outs


def test_requirement_severity_change_risk_and_enforcement_are_separate(tmp_path):
    root = _make(tmp_path)
    p = evaluate_proposal(root, "app.py", content=ORIG.replace("LIMIT = 3", "LIMIT = 3  # note"))
    sev = p.affected_requirements[0]["severity"]
    assert sev == "critical"                       # requirement severity (registered)
    assert p.assessed_risk == "LOW"                # change risk (this edit)
    assert p.decision == "FORCE_ASK"               # enforcement (still reviewed)
    assert p.analysis_status == "CONFIRMED_AFFECTED"
