
from __future__ import annotations

import hashlib
import sys
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
from winotify import Notification

from .ledger import list_requirements, mark_changed_files
from .security_scanner import scan_file


IGNORED_PARTS = {
    ".git",
    ".securetrace",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "node_modules",
}

_alert_lock = threading.Lock()
_recent_alerts: set[str] = set()


def is_ignored(path: Path) -> bool:
    """Return True when a path belongs to an ignored directory."""
    return any(part in IGNORED_PARTS for part in path.parts)


def normalize_relative_path(path: str) -> str:
    """Normalize ledger and watcher paths for comparison."""
    return Path(path).as_posix().removeprefix("./").casefold()


def send_desktop_notification(title: str, message: str) -> None:
    """Show a Windows desktop notification for SecureTrace."""
    try:
        Notification(
            app_id="SecureTrace",
            title=title[:100],
            msg=message[:500],
        ).show()
    except Exception as exc:
        print(
            f"[SecureTrace] Desktop notification failed: {exc}",
            file=sys.stderr,
            flush=True,
        )


def should_alert(finding: dict) -> bool:
    """Suppress duplicate findings during this watcher session."""
    identity = "|".join(
        str(finding.get(key, ""))
        for key in ("rule_id", "file", "line", "evidence")
    )
    key = hashlib.sha256(identity.encode("utf-8")).hexdigest()

    with _alert_lock:
        if key in _recent_alerts:
            return False
        _recent_alerts.add(key)
        return True


class SecureTraceHandler(FileSystemEventHandler):
    """Scan changed files and record affected requirements."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def on_any_event(self, event) -> None:
        if event.is_directory:
            return

        if event.event_type not in {
            "created",
            "modified",
            "deleted",
            "moved",
        }:
            return

        paths = [Path(event.src_path)]
        destination = getattr(event, "dest_path", None)
        if destination:
            paths.append(Path(destination))

        relative_paths: list[str] = []

        for path in paths:
            try:
                resolved = path.resolve()
                if is_ignored(resolved):
                    continue

                relative_paths.append(
                    resolved.relative_to(self.root).as_posix()
                )
            except (ValueError, OSError, RuntimeError):
                continue

        relative_paths = list(dict.fromkeys(relative_paths))
        if not relative_paths:
            return

        # Record changes and discover affected requirements.
        try:
            affected = mark_changed_files(self.root, relative_paths)
        except Exception as exc:
            print(
                f"[SecureTrace] Change processing failed: {exc}",
                file=sys.stderr,
                flush=True,
            )
            affected = []

        # Load requirement titles and file mappings.
        try:
            requirements = list_requirements(self.root)
        except Exception as exc:
            print(
                f"[SecureTrace] Could not load requirement titles: {exc}",
                file=sys.stderr,
                flush=True,
            )
            requirements = []

        requirements_by_file: dict[str, list[dict]] = {}

        for requirement in requirements:
            for linked_file in requirement.get("file_paths", []):
                key = normalize_relative_path(linked_file)
                requirements_by_file.setdefault(key, []).append({
                    "id": requirement.get("id", "Unknown ID"),
                    "title": requirement.get(
                        "title", "Untitled requirement"
                    ),
                })

        affected_ids = {
            item.get("requirement_id")
            for item in affected
        }

        # Scan changed files for potential security risks.
        for relative_path in relative_paths:
            changed_path = self.root / relative_path

            if not changed_path.is_file():
                continue

            try:
                findings = scan_file(changed_path)
            except Exception as exc:
                print(
                    f"[SecureTrace] Scanner failed for "
                    f"{relative_path}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
                continue

            file_key = normalize_relative_path(relative_path)

            linked_requirements = [
                requirement
                for requirement in requirements_by_file.get(file_key, [])
                if requirement["id"] in affected_ids
            ]

            if linked_requirements:
                requirement_text = "; ".join(
                    f'{item["id"]} â€” {item["title"]}'
                    for item in linked_requirements
                )
            else:
                requirement_text = "No linked requirement found"

            # Group security notifications by requirement for this file.
            alerted_requirements: set[str] = set()

            for finding in findings:
                if not should_alert(finding):
                    continue

                severity = finding.get("severity", "REVIEW")
                title = finding.get(
                    "title", "Potential security risk"
                )
                line = finding.get("line", "?")
                attack = finding.get(
                    "attack", "Review the changed code."
                )
                action = finding.get(
                    "action", "Investigate this finding."
                )

                # Keep every distinct finding visible in the terminal.
                print(
                    f"[SecureTrace] Potential risk: {title} "
                    f"in {relative_path}:{line}; "
                    f"requirements: {requirement_text}",
                    file=sys.stderr,
                    flush=True,
                )

                alert_key = (
                    requirement_text
                    if requirement_text != "No linked requirement found"
                    else f"file:{file_key}"
                )

                if alert_key in alerted_requirements:
                    continue

                alerted_requirements.add(alert_key)

                send_desktop_notification(
                    f"SecureTrace - {severity} security risk",
                    (
                        f"{title}\n"
                        f"File: {relative_path}:{line}\n"
                        f"Requirement: {requirement_text}\n"
                        f"Potential harm: {attack}\n"
                        f"Action: {action}"
                    ),
                )

        # Preserve requirement-change notifications with titles.
        for item in affected:
            requirement_id = item["requirement_id"]
            changed_files = ", ".join(item["changed_files"])

            requirement = next(
                (
                    req for req in requirements
                    if req.get("id") == requirement_id
                ),
                None,
            )

            requirement_title = (
                requirement.get("title", "")
                if requirement
                else ""
            )

            message = f"{requirement_id}\nChanged: {changed_files}"

            if requirement_title:
                message = (
                    f"{requirement_id}\n"
                    f"{requirement_title}\n"
                    f"Changed: {changed_files}"
                )

            print(
                "[SecureTrace] Linked requirement affected: "
                f"{requirement_id}"
                + (
                    f" â€” {requirement_title}"
                    if requirement_title
                    else ""
                )
                + f" (changed: {changed_files})",
                file=sys.stderr,
                flush=True,
            )

            send_desktop_notification(
                "SecureTrace - Requirement affected",
                message,
            )


def start_watcher(root: Path) -> Observer:
    """Start a recursive filesystem observer."""
    root = root.resolve()

    if not root.is_dir():
        raise NotADirectoryError(
            f"SecureTrace project root is not a directory: {root}"
        )

    observer = Observer()
    observer.schedule(
        SecureTraceHandler(root),
        str(root),
        recursive=True,
    )

    try:
        observer.start()
    except Exception:
        observer.stop()
        observer.join()
        raise

    print(
        f"[SecureTrace] Watching project: {root}",
        file=sys.stderr,
        flush=True,
    )
    return observer


def stop_watcher(observer: Observer) -> None:
    """Stop the observer and wait for it to finish."""
    observer.stop()
    observer.join()


def watch(root: Path) -> None:
    """Run the standalone watcher until interrupted."""
    observer = start_watcher(root)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(
            "[SecureTrace] Stopping watcher.",
            file=sys.stderr,
            flush=True,
        )
    finally:
        stop_watcher(observer)

