from __future__ import annotations

import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
from urllib.parse import urlparse

from .db import database_path
from .ledger import (
    VALID_CATEGORIES,
    VALID_SEVERITIES,
    add_requirement,
    decode_check_record,
    mark_changed_files,
    record_check,
)
from .reporting import render_report

STATUSES = ("IDENTIFIED", "IMPLEMENTED", "VERIFIED", "STALE", "REGRESSION")
HOST = "127.0.0.1"
MAX_REQUEST_BYTES = 16_384


def _required_text(payload: dict, field: str, label: str, limit: int = 4000) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} is required.")
    value = value.strip()
    if len(value) > limit:
        raise ValueError(f"{label} must be {limit} characters or fewer.")
    return value


def _safe_relative_paths(values: object) -> list[str]:
    if not isinstance(values, list):
        raise ValueError("File paths must be provided as a list.")
    if len(values) > 100:
        raise ValueError("Provide no more than 100 file paths at a time.")
    paths = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Each file path must be a non-empty string.")
        path = value.strip().replace("\\", "/")
        if path.startswith("/") or re.match(r"^[A-Za-z]:", path):
            raise ValueError(f"File paths must be relative to the repository: {value}")
        if "\x00" in path or ".." in path.split("/"):
            raise ValueError(f"Path traversal is not allowed: {value}")
        path = "/".join(part for part in path.split("/") if part not in {"", "."})
        if not path:
            raise ValueError("File paths must name a file inside the repository.")
        paths.append(path)
    return list(dict.fromkeys(paths))


def _read_connection(root: Path) -> sqlite3.Connection:
    path = database_path(root).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"SecureTrace database not found: {path}")
    connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only = ON")
    return connection


def read_dashboard_data(root: Path) -> dict:
    """Read a ledger snapshot without schema initialization or database writes."""
    root = root.resolve()
    with _read_connection(root) as db:
        mapping_schema = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='requirement_tests'").fetchone()
        mappings_by_id: dict[str, list[dict]] = {}
        if mapping_schema:
            for mapping in db.execute(
                "SELECT requirement_id,test_file,test_id,verification_complete,created_at FROM requirement_tests ORDER BY test_file,test_id"
            ):
                mappings_by_id.setdefault(mapping["requirement_id"], []).append(dict(mapping))
        rows = db.execute(
            """SELECT r.*, GROUP_CONCAT(rf.file_path, '|||') AS linked_files
               FROM requirements r
               LEFT JOIN requirement_files rf ON rf.requirement_id = r.id
               GROUP BY r.id ORDER BY r.created_at DESC"""
        ).fetchall()
        scanner_events = [dict(event) for event in db.execute(
            "SELECT event_type,details,created_at FROM events WHERE event_type='SEMGREP_SCAN' "
            "ORDER BY created_at DESC,id DESC LIMIT 20"
        )]
        recent_changes = [dict(event) for event in db.execute(
            """SELECT e.id, e.requirement_id, e.event_type, e.details, e.created_at,
                      r.title AS requirement_title, r.status AS requirement_status
               FROM events e
               LEFT JOIN requirements r ON r.id = e.requirement_id
               WHERE e.event_type = 'LINKED_FILE_CHANGED'
               ORDER BY e.created_at DESC, e.id DESC
               LIMIT 30"""
        )]
        requirements = []
        details_by_id = {}
        for row in rows:
            item = dict(row)
            linked = item.pop("linked_files", None)
            item["file_paths"] = linked.split("|||") if linked else []
            requirements.append(item)
            details_by_id[item["id"]] = {
                "checks": [decode_check_record(dict(check)) for check in db.execute(
                    "SELECT * FROM checks WHERE requirement_id = ? ORDER BY ran_at DESC, id DESC",
                    (item["id"],),
                )],
                "events": [dict(event) for event in db.execute(
                    "SELECT * FROM events WHERE requirement_id = ? ORDER BY created_at DESC, id DESC",
                    (item["id"],),
                )],
            }

    counts = {status: 0 for status in STATUSES}
    for item in requirements:
        if item["status"] in counts:
            counts[item["status"]] += 1
    report = render_report(root, requirements=requirements, details_by_id=details_by_id,
                           mappings_by_id=mappings_by_id, scanner_events=scanner_events)
    return {
        "repository": str(root), "total": len(requirements), "counts": counts,
        "requirements": requirements, "details": details_by_id,
        "recent_changes": recent_changes, "report": report,
    }


def check_details_for_display(check: dict) -> tuple[str, str]:
    """Return a provenance label and safe details from a stored check row."""
    raw = check.get("details", "")
    if check.get("provenance") == "manual":
        return "manually recorded", raw
    if check.get("provenance") == "automated":
        try:
            metadata = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            return "automatically executed", "Execution metadata unavailable."
        summary = f"Executed test; outcome {metadata.get('outcome')}; exit code {metadata.get('exit_code')}."
        if metadata.get("evidence_ref"):
            summary += f" Evidence: {metadata['evidence_ref']}"
        return "automatically executed", summary
    try:
        metadata = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return "manually recorded", raw
    if isinstance(metadata, dict) and metadata.get("securetrace_test") == 1 and metadata.get("origin") == "automated":
        summary = f"Executed test; outcome {metadata.get('outcome')}; exit code {metadata.get('exit_code')}."
        if metadata.get("evidence_ref"):
            summary += f" Evidence: {metadata['evidence_ref']}"
        return "automatically executed", summary
    if isinstance(metadata, dict) and metadata.get("securetrace_provenance") == 1:
        return "manually recorded", str(metadata.get("details", ""))
    return "manually recorded", raw


def answer_question(data: dict, question: str) -> str:
    """Answer basic questions using only requirement, check, and event data."""
    question = question.strip()
    if not question:
        return "Ask about a requirement by its ID or title."
    lowered = question.casefold()
    asks_how_many = bool(re.search(r"\b(how many|count|counts|number of)\b", lowered))
    asks_all_statuses = bool(
        re.search(r"\b(all|each|every)\b.*\b(status|statuses)\b", lowered)
        or re.search(r"\b(status|statuses)\s+counts\b", lowered)
    )
    asks_total = bool(
        re.search(r"\b(requirements?)\b.*\b(tracked|total)\b", lowered)
        or re.search(r"\b(tracked|total)\b.*\b(requirements?)\b", lowered)
    ) and asks_how_many
    asks_stale = bool(re.search(r"\b(stale|staleness)\b", lowered)) and asks_how_many
    if asks_all_statuses:
        counts = data["counts"]
        summary = ", ".join(f"{status}: {counts.get(status, 0)}" for status in STATUSES)
        return f"Status counts — {summary}. Total requirements: {data['total']}."
    if asks_total or asks_stale:
        parts = []
        if asks_total:
            parts.append(f"{data['total']} requirements are tracked")
        if asks_stale:
            stale_count = data["counts"].get("STALE", 0)
            noun = "requirement" if stale_count == 1 else "requirements"
            verb = "is" if stale_count == 1 else "are"
            parts.append(f"{stale_count} {noun} {verb} stale")
        return "In the current ledger, " + " and ".join(parts) + "."

    by_id = re.search(r"\bSEC-[A-Z0-9]+\b", question, re.IGNORECASE)
    if by_id:
        matches = [r for r in data["requirements"] if r["id"].casefold() == by_id.group().casefold()]
    else:
        matches = [r for r in data["requirements"] if r["title"].casefold() in lowered]
        if not matches:
            terms = [term for term in re.findall(r"[\w-]+", lowered) if len(term) > 3]
            matches = [r for r in data["requirements"] if any(term in r["title"].casefold() for term in terms)]
    if not matches:
        return "I couldn't match that question to a requirement in the current ledger. Include its SEC-… ID or title."
    if len(matches) > 1:
        return "I found multiple matching requirements: " + ", ".join(
            f"{r['id']} ({r['title']})" for r in matches
        ) + ". Please specify one ID."

    item = matches[0]
    details = data["details"].get(item["id"], {})
    checks, events = details.get("checks", []), details.get("events", [])
    lines = [f"{item['id']} — {item['title']} is {item['status']} (severity: {item['severity']})."]
    if item["status"] == "STALE":
        change = next((e for e in events if e["event_type"] == "LINKED_FILE_CHANGED"), None)
        if change:
            lines.append(f"The ledger records a linked file change at {change['created_at']}: {change['details']}")
        else:
            lines.append("The ledger marks it STALE, but contains no linked-file-change event to explain when it became stale.")
        if checks:
            latest = checks[0]
            provenance, check_details = check_details_for_display(latest)
            lines.append(
                f"Latest check: {latest['check_name']} — {latest['result']} "
                f"(complete verification: {'yes' if latest['verification_complete'] else 'no'}; "
                f"{provenance})."
            )
            if check_details:
                lines.append(f"Check details: {check_details}")
        lines.append("A passing recorded check is evidence for that check; it does not guarantee that the application is secure.")
    elif checks:
        latest = checks[0]
        provenance, check_details = check_details_for_display(latest)
        lines.append(
            f"Latest check: {latest['check_name']} — {latest['result']} "
            f"(complete verification: {'yes' if latest['verification_complete'] else 'no'}; "
            f"{provenance})."
        )
        if check_details:
            lines.append(f"Check details: {check_details}")
    else:
        lines.append("No checks are recorded for this requirement.")
    return "\n".join(lines)


def perform_action(root: Path, action: str, payload: dict) -> dict:
    """Run one explicitly supported dashboard write against the existing ledger API."""
    if payload.get("confirmed") is not True:
        raise ValueError("Confirm this state-changing action before submitting it.")

    if action == "add-requirement":
        title = _required_text(payload, "title", "Title", 300)
        description = _required_text(payload, "description", "Description")
        category = payload.get("category")
        severity = payload.get("severity")
        if not isinstance(category, str) or category not in VALID_CATEGORIES:
            raise ValueError(f"Category must be one of: {', '.join(sorted(VALID_CATEGORIES))}.")
        if not isinstance(severity, str) or severity not in VALID_SEVERITIES:
            raise ValueError(f"Severity must be one of: {', '.join(sorted(VALID_SEVERITIES))}.")
        paths = _safe_relative_paths(payload.get("file_paths", []))
        result = add_requirement(root, title, description, category, severity, paths)
        message = f"Added requirement {result['id']}. No test was run by this action."
    elif action == "record-check":
        requirement_id = _required_text(payload, "requirement_id", "Requirement", 100)
        check_name = _required_text(payload, "check_name", "Check name", 300)
        details = payload.get("details", "")
        if not isinstance(details, str) or len(details) > 4000:
            raise ValueError("Details must be 4000 characters or fewer.")
        result_value = payload.get("result")
        if not isinstance(result_value, str) or result_value not in {"PASSED", "FAILED"}:
            raise ValueError("Result must be PASSED or FAILED.")
        verification_complete = payload.get("verification_complete")
        if not isinstance(verification_complete, bool):
            raise ValueError("Choose whether verification is complete.")
        result = record_check(
            root,
            requirement_id,
            check_name,
            passed=result_value == "PASSED",
            details=details,
            verification_complete=verification_complete,
        )
        message = (
            f"Recorded {result['result']} evidence for {requirement_id}. "
            "This action records your report; it did not execute a test."
        )
    elif action == "mark-changed-files":
        paths = _safe_relative_paths(payload.get("file_paths"))
        if not paths:
            raise ValueError("Enter at least one relative file path.")
        result = mark_changed_files(root, paths)
        if result:
            affected = "; ".join(
                f"{item['requirement_id']}: {', '.join(item['changed_files'])}" for item in result
            )
            message = f"Marked {len(result)} linked requirement(s) for re-verification. Affected: {affected}"
        else:
            message = "No linked requirements matched those file paths."
    else:
        raise ValueError("Unsupported dashboard action.")

    return {"message": message, "result": result, "data": read_dashboard_data(root)}


PAGE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureTrace Dashboard</title><style>
:root{color-scheme:dark;--bg:#0c1220;--panel:#141d2e;--line:#27354c;--text:#e8eef8;--muted:#9aabc3;--blue:#77aaff;--green:#5bd1a0;--amber:#ffc66d;--red:#ff8290}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,sans-serif}header{padding:26px max(24px,calc((100% - 1240px)/2));border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center}h1{margin:0;font-size:22px}header p,.muted{color:var(--muted);margin:4px 0 0}.layout{max-width:1240px;margin:24px auto;padding:0 24px;display:grid;grid-template-columns:minmax(0,1.5fr) minmax(320px,.8fr);gap:20px}.main{min-width:0}.cards{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}.card,.panel,.requirement{background:var(--panel);border:1px solid var(--line);border-radius:12px}.card{padding:14px}.card strong{display:block;font-size:26px}.card span{font-size:11px;color:var(--muted);letter-spacing:.06em}.section-title{font-size:17px;margin:20px 0 10px}.requirement{padding:16px;margin-bottom:10px}.req-head{display:flex;justify-content:space-between;gap:14px}.req-head h3{margin:0;font-size:16px}.badge{font-size:11px;font-weight:700;padding:4px 8px;border-radius:20px;background:#25354d;white-space:nowrap}.STALE,.IMPLEMENTED{color:var(--amber)}.VERIFIED{color:var(--green)}.REGRESSION{color:var(--red)}.IDENTIFIED{color:var(--blue)}.meta{color:var(--muted);font-size:13px;margin:8px 0}.files code{display:inline-block;background:#202d41;padding:2px 6px;border-radius:5px;margin:2px;font-size:12px}.latest{border-top:1px solid var(--line);padding-top:9px;margin-top:10px;font-size:13px}.panel{padding:16px}.sticky{position:sticky;top:16px;height:max-content}.panel h2{margin:0 0 12px;font-size:17px}#chat-log{height:330px;overflow:auto;border:1px solid var(--line);border-radius:8px;padding:10px;margin-bottom:10px;white-space:pre-wrap}.message{padding:9px;margin:6px 0;border-radius:8px;background:#1c2940}.message.user{color:var(--blue)}form{display:flex;gap:8px}input,button{font:inherit;border-radius:8px;border:1px solid var(--line);padding:10px;background:#10192a;color:var(--text)}input{min-width:0;flex:1}button{background:#315fa4;border:0;cursor:pointer}#report{white-space:pre-wrap;overflow:auto;max-height:440px;font:12px/1.6 ui-monospace,monospace;color:#c4d1e3}.notice{color:var(--muted);font-size:12px;margin-top:14px}@media(max-width:900px){.layout{grid-template-columns:1fr}.sticky{position:static}.cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:500px){.cards{grid-template-columns:repeat(2,1fr)}}
</style></head><body><header><div><h1>SecureTrace</h1><p id="repository">Loading ledger…</p></div><span class="badge">LOCAL DASHBOARD</span></header>
<div class="layout"><main class="main"><section class="cards" id="counts"></section><h2 class="section-title">Recent Changes <span class="muted" id="live-status">Connecting?</span></h2><section class="panel" id="recent-changes"><p class="muted">Loading file-change events?</p></section><h2 class="section-title">Requirements</h2><section id="requirements"></section><section class="panel"><h2>Security report</h2><pre id="report">Loading report…</pre></section></main>
<aside class="panel sticky"><h2>Ask about the ledger</h2><div id="chat-log" aria-live="polite"></div><form id="chat-form"><input id="question" aria-label="Question" placeholder="Why is SEC-… stale?" autocomplete="off"><button>Ask</button></form><p class="notice">Answers use recorded ledger data only. A passing check does not guarantee application security.</p></aside></div>
<script>
const el=id=>document.getElementById(id);function add(tag,parent,text,cls){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;parent.appendChild(n);return n}
function render(d){if(window.dashboardRender){window.dashboardRender(d);return}el('repository').textContent=d.repository+' · '+d.total+' requirements';const cards=el('counts');for(const s of ['IDENTIFIED','IMPLEMENTED','VERIFIED','STALE','REGRESSION']){const c=add('div',cards,undefined,'card');add('strong',c,String(d.counts[s]));add('span',c,s)}const list=el('requirements');if(!d.requirements.length)add('p',list,'No requirements have been registered.','muted');for(const r of d.requirements){const card=add('article',list,undefined,'requirement');const head=add('div',card,undefined,'req-head');add('h3',head,r.id+' · '+r.title);add('span',head,r.status,'badge '+r.status);add('p',card,r.description,'meta');add('p',card,'Severity: '+r.severity+' · Category: '+r.category,'meta');const files=add('div',card,undefined,'files');for(const f of r.file_paths)add('code',files,f);const latest=((d.details[r.id]||{}).checks||[])[0],summary=latest?latest.check_name+': '+latest.result+' · complete verification: '+(latest.verification_complete?'yes':'no')+(latest.details?' · '+latest.details:''):'No checks recorded.';add('div',card,'Latest check: '+summary,'latest')}el('report').textContent=d.report}
function message(who,text){const n=add('div',el('chat-log'),text,'message '+who);el('chat-log').scrollTop=el('chat-log').scrollHeight;return n}
el('chat-form').addEventListener('submit',async e=>{e.preventDefault();const q=el('question').value.trim();if(!q)return;el('question').value='';message('user',q);try{const res=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({question:q})});const body=await res.json();message('assistant',body.answer||body.error)}catch{message('assistant','Could not reach the local dashboard.')}});
async function refreshDashboard(){try{const r=await fetch('/api/dashboard',{cache:'no-store'});if(!r.ok)throw Error();render(await r.json());const live=el('live-status');if(live)live.textContent='Live ? updated '+new Date().toLocaleTimeString()}catch{const live=el('live-status');if(live)live.textContent='Refresh failed ? check dashboard connection'}}refreshDashboard();setInterval(refreshDashboard,3000);
</script><script>
// Keep the existing dashboard document compact while adding fixed ledger forms.
const actionStyle=document.createElement('style');actionStyle.textContent='.action-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin:18px 0}.action-form{display:grid;gap:8px;align-content:start}.action-form input,.action-form textarea,.action-form select{width:100%;min-width:0}.action-form textarea{min-height:64px}.action-form label{font-size:12px;color:#9aabc3}.action-note{font-size:12px;color:#ffc66d;margin:0}.feedback{padding:10px;margin:10px 0;border-radius:8px;white-space:pre-wrap}.feedback.success{background:#1b382f;color:#5bd1a0}.feedback.error{background:#3a222c;color:#ff8290}';document.head.append(actionStyle);
el('counts').insertAdjacentHTML('afterend',`<h2 class="section-title">Ledger actions</h2><div id="feedback" role="status"></div><section class="action-grid">
<form id="add-form" class="panel action-form"><h2>Add Requirement</h2><label>Title<input name="title" required maxlength="300"></label><label>Description<textarea name="description" required maxlength="4000"></textarea></label><label>Category<select name="category"><option>authentication</option><option>authorization</option><option>data-handling</option><option>secrets</option><option>dependencies</option><option>configuration</option><option selected>other</option></select></label><label>Severity<select name="severity"><option>low</option><option selected>medium</option><option>high</option><option>critical</option></select></label><label>Linked relative file paths, one per line<textarea name="file_paths" placeholder="src/routes/example.py"></textarea></label><button>Add requirement</button></form>
<form id="check-form" class="panel action-form"><h2>Record Check Evidence</h2><p class="action-note">This records what you report. It does not execute a security test.</p><label>Requirement<select name="requirement_id" required></select></label><label>Check name<input name="check_name" required maxlength="300"></label><label>Recorded result<select name="result"><option>PASSED</option><option>FAILED</option></select></label><label>Details<textarea name="details" maxlength="4000"></textarea></label><label>Was verification completed independently?<select name="verification_complete" required><option value="" selected>Choose explicitly</option><option value="false">No, not complete</option><option value="true">Yes, complete verification</option></select></label><button>Record evidence</button></form>
<form id="changed-form" class="panel action-form"><h2>Mark Changed Files</h2><label>Repository-relative paths, one per line<textarea name="file_paths" required placeholder="src/routes/example.py"></textarea></label><p class="action-note">Linked requirements may become stale and need re-verification.</p><button>Mark files changed</button></form></section>`);
function render(d){el('repository').textContent=d.repository+' · '+d.total+' requirements';const feed=el('recent-changes');feed.replaceChildren();const changes=d.recent_changes||[];if(!changes.length)add('p',feed,'No linked file changes recorded yet.','muted');for(const ev of changes){const item=add('article',feed,undefined,'requirement');const head=add('div',item,undefined,'req-head');add('strong',head,ev.details||'Linked file changed');add('span',head,ev.requirement_status||'EVENT','badge '+(ev.requirement_status||''));add('p',item,(ev.requirement_id||'Unlinked')+' ? '+(ev.requirement_title||'No matching requirement'),'meta');add('p',item,ev.created_at||'Timestamp unavailable','meta')}const cards=el('counts');cards.replaceChildren();for(const s of ['IDENTIFIED','IMPLEMENTED','VERIFIED','STALE','REGRESSION']){const c=add('div',cards,undefined,'card');add('strong',c,String(d.counts[s]));add('span',c,s)}const list=el('requirements');list.replaceChildren();const select=document.querySelector('#check-form [name=requirement_id]'),old=select.value;select.replaceChildren();for(const r of d.requirements){const option=add('option',select,r.id+' · '+r.title);option.value=r.id}if(old)select.value=old;if(!d.requirements.length){const option=add('option',select,'No requirements available');option.value='';option.disabled=true;add('p',list,'No requirements have been registered.','muted')}for(const r of d.requirements){const card=add('article',list,undefined,'requirement'),head=add('div',card,undefined,'req-head');add('h3',head,r.id+' · '+r.title);add('span',head,r.status,'badge '+r.status);add('p',card,r.description,'meta');add('p',card,'Severity: '+r.severity+' · Category: '+r.category,'meta');const files=add('div',card,undefined,'files');for(const f of r.file_paths)add('code',files,f);const latest=((d.details[r.id]||{}).checks||[])[0];let metadata=null;try{metadata=latest?JSON.parse(latest.details):null}catch{}const automated=metadata&&metadata.securetrace_test===1&&metadata.origin==='automated',manualDetails=metadata&&metadata.securetrace_provenance===1?metadata.details:(latest?latest.details:''),summary=latest?latest.check_name+': '+latest.result+' · '+(automated?'automatically executed':'manually recorded')+' · complete verification: '+(latest.verification_complete?'yes':'no')+(automated?' · exit '+metadata.exit_code+' · duration '+metadata.duration_seconds+'s'+(metadata.evidence_ref?' · evidence '+metadata.evidence_ref:''):' · not executed by dashboard')+(manualDetails?' · '+manualDetails:''):'No checks recorded.';add('div',card,'Latest check: '+summary,'latest')}el('report').textContent=d.report;if(window.reportStatus)window.reportStatus.textContent='Report refreshed from the latest ledger snapshot.'}
const reportHeading=el('report').parentElement.querySelector('h2');
const reportButton=document.createElement('button');reportButton.id='generate-report';reportButton.type='button';reportButton.textContent='Generate Security Report';reportHeading.append(reportButton);
const reportStatus=document.createElement('p');window.reportStatus=reportStatus;reportStatus.id='report-status';reportStatus.className='notice';reportStatus.setAttribute('role','status');reportHeading.after(reportStatus);
reportButton.addEventListener('click',async()=>{reportButton.disabled=true;reportStatus.textContent='Generating report from the current ledger?';try{const response=await fetch('/api/report',{method:'GET',cache:'no-store'}),body=await response.json();if(!response.ok||typeof body.report!=='string')throw Error(body.error||'Report generation failed.');el('report').textContent=body.report;reportStatus.textContent='Report generated from the current SecureTrace ledger.'}catch(error){reportStatus.textContent=error.message}finally{reportButton.disabled=false}});
window.dashboardRender=render;
function showActionFeedback(text,isError){const box=el('feedback');box.className='feedback '+(isError?'error':'success');box.textContent=text}
function pathLines(value){return value.split(/\r?\n/).map(path=>path.trim()).filter(Boolean)}
async function submitAction(form,url,payload,confirmation){if(!window.confirm(confirmation))return;const button=form.querySelector('button');button.disabled=true;try{const response=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...payload,confirmed:true})}),body=await response.json();if(!response.ok)throw Error(body.error||'Action failed.');render(body.data);showActionFeedback(body.message,false);form.reset()}catch(error){showActionFeedback(error.message,true)}finally{button.disabled=false}}
document.querySelector('#add-form').addEventListener('submit',event=>{event.preventDefault();const f=event.currentTarget;submitAction(f,'/api/actions/add-requirement',{title:f.elements.title.value,description:f.elements.description.value,category:f.elements.category.value,severity:f.elements.severity.value,file_paths:pathLines(f.elements.file_paths.value)},'Add this requirement to the ledger?')});
document.querySelector('#check-form').addEventListener('submit',event=>{event.preventDefault();const f=event.currentTarget;if(!f.elements.verification_complete.value){showActionFeedback('Choose whether verification is complete.',true);return}submitAction(f,'/api/actions/record-check',{requirement_id:f.elements.requirement_id.value,check_name:f.elements.check_name.value,details:f.elements.details.value,result:f.elements.result.value,verification_complete:f.elements.verification_complete.value==='true'},'Record this result as evidence? SecureTrace will not execute a test.')});
document.querySelector('#changed-form').addEventListener('submit',event=>{event.preventDefault();const f=event.currentTarget;submitAction(f,'/api/actions/mark-changed-files',{file_paths:pathLines(f.elements.file_paths.value)},'Mark these linked file paths as changed? Matching requirements may become stale.')});
</script></body></html>"""


def make_handler(root: Path):
    class DashboardHandler(BaseHTTPRequestHandler):
        def _json(self, payload: dict, status: int = 200) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/":
                body = PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(body)
            elif path == "/api/dashboard":
                try:
                    self._json(read_dashboard_data(root))
                except (OSError, sqlite3.Error) as exc:
                    self._json({"error": str(exc)}, 503)
            elif path == "/api/report" and self.path == "/api/report":
                try:
                    # Snapshot reads are read-only and render_report supplies the canonical Markdown.
                    self._json({"report": read_dashboard_data(root)["report"]})
                except (OSError, sqlite3.Error) as exc:
                    self._json({"error": str(exc)}, 503)
            else:
                self._json({"error": "Not found"}, 404)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path not in {
                "/api/chat",
                "/api/actions/add-requirement",
                "/api/actions/record-check",
                "/api/actions/mark-changed-files",
            }:
                self._json({"error": "Not found"}, 404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > MAX_REQUEST_BYTES:
                    raise ValueError(f"Request body must be between 1 and {MAX_REQUEST_BYTES} bytes")
                payload = json.loads(self.rfile.read(length))
                if not isinstance(payload, dict):
                    raise ValueError("Request body must be a JSON object")
                if path == "/api/chat":
                    if not isinstance(payload.get("question"), str):
                        raise ValueError("Provide a question string")
                    self._json({"answer": answer_question(read_dashboard_data(root), payload["question"])})
                else:
                    action = path.removeprefix("/api/actions/")
                    self._json(perform_action(root, action, payload))
            except (ValueError, json.JSONDecodeError) as exc:
                self._json({"error": str(exc)}, 400)
            except (OSError, sqlite3.Error) as exc:
                self._json({"error": str(exc)}, 503)

        def log_message(self, fmt: str, *args) -> None:
            print(f"[SecureTrace dashboard] {self.address_string()} - {fmt % args}")

    return DashboardHandler


def create_server(root: Path, port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((HOST, port), make_handler(root.resolve()))


def serve(root: Path, port: int = 8765) -> None:
    server = create_server(root, port)
    print(f"SecureTrace dashboard: http://{HOST}:{server.server_port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SecureTrace dashboard.")
    finally:
        server.server_close()
