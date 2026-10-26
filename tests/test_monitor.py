
from pathlib import Path
from unittest.mock import Mock

import securetrace.monitor as monitor


def test_start_watcher_starts_recursive_observer(monkeypatch, tmp_path):
    fake_observer = Mock()
    monkeypatch.setattr(
        monitor,
        "Observer",
        lambda: fake_observer,
    )

    observer = monitor.start_watcher(tmp_path)

    assert observer is fake_observer
    fake_observer.schedule.assert_called_once()
    fake_observer.start.assert_called_once()

    args, kwargs = fake_observer.schedule.call_args
    assert args[1] == str(tmp_path.resolve())
    assert kwargs["recursive"] is True


def test_stop_watcher_stops_and_joins_observer():
    fake_observer = Mock()

    monitor.stop_watcher(fake_observer)

    fake_observer.stop.assert_called_once()
    fake_observer.join.assert_called_once()


def test_start_watcher_rejects_missing_root(tmp_path):
    missing_root = tmp_path / "does-not-exist"

    try:
        monitor.start_watcher(missing_root)
    except NotADirectoryError:
        pass
    else:
        raise AssertionError("Expected NotADirectoryError")


def test_handler_forwards_modified_file_to_ledger(
    monkeypatch,
    tmp_path,
):
    project_file = tmp_path / "example.py"
    project_file.write_text("# test", encoding="utf-8")

    mark_changed = Mock(return_value=[])

    monkeypatch.setattr(
        monitor,
        "mark_changed_files",
        mark_changed,
    )

    handler = monitor.SecureTraceHandler(tmp_path)

    event = Mock()
    event.is_directory = False
    event.event_type = "modified"
    event.src_path = str(project_file)
    event.dest_path = ""

    handler.on_any_event(event)

    mark_changed.assert_called_once_with(
        tmp_path.resolve(),
        ["example.py"],
    )


def test_handler_ignores_securetrace_directory(
    monkeypatch,
    tmp_path,
):
    ignored_dir = tmp_path / ".securetrace"
    ignored_dir.mkdir()
    ignored_file = ignored_dir / "test.db"
    ignored_file.touch()

    mark_changed = Mock()
    monkeypatch.setattr(
        monitor,
        "mark_changed_files",
        mark_changed,
    )

    handler = monitor.SecureTraceHandler(tmp_path)

    event = Mock()
    event.is_directory = False
    event.event_type = "modified"
    event.src_path = str(ignored_file)
    event.dest_path = ""

    handler.on_any_event(event)

    mark_changed.assert_not_called()
