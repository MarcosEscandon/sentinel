"""Real-time monitoring of new or modified files.

The :class:`RealtimeMonitor` watches directories (recursively) and individual
files. On Windows it uses a native backend based on ``ctypes`` and
``ReadDirectoryChangesW``; it then tries ``watchdog`` and, as a last resort,
an ``os.stat`` polling loop that requires no external dependencies.
All analysis is performed by a single worker thread that consumes a queue
of pending paths.
"""

from __future__ import annotations

import ctypes
import os
import queue
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from .config import ScanConfig
from .core.allowlist import AllowList, normalize_path
from .core.logging import AuditLogger
from .core.models import Finding, ScanResult
from .core.quarantine import Quarantine
from .engine.scanner import Scanner
from .engine.signatures import SignatureDatabase

FILE_ATTRIBUTE_REPARSE_POINT = 0x400

# Constants and structures of the native Windows backend (pure ctypes).
# Declared on all platforms so the module remains importable on systems
# where ``ctypes.WinDLL`` does not exist.
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_READ = 0x0001
_FILE_SHARE_WRITE = 0x0002
_FILE_SHARE_DELETE = 0x0004
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OVERLAPPED = 0x40000000
_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_FILE_NOTIFY_CHANGE_CREATION = 0x00000040
_NOTIFY_FILTER = (
    _FILE_NOTIFY_CHANGE_FILE_NAME
    | _FILE_NOTIFY_CHANGE_SIZE
    | _FILE_NOTIFY_CHANGE_LAST_WRITE
    | _FILE_NOTIFY_CHANGE_CREATION
)
_FILE_ACTION_ADDED = 0x00000001
_FILE_ACTION_MODIFIED = 0x00000003
_FILE_ACTION_RENAMED_NEW_NAME = 0x00000005
_WATCHED_ACTIONS = frozenset(
    {_FILE_ACTION_ADDED, _FILE_ACTION_MODIFIED, _FILE_ACTION_RENAMED_NEW_NAME}
)
_NATIVE_BUFFER_SIZE = 64 * 1024
_NATIVE_WAIT_MS = 200
_ERROR_OPERATION_ABORTED = 995
_ERROR_INSUFFICIENT_BUFFER = 122
_WAIT_OBJECT_0 = 0x00000000
_WAIT_FAILED = 0xFFFFFFFF
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_DWORD = ctypes.c_ulong
_BOOL = ctypes.c_int
_HANDLE = ctypes.c_void_p
_LPVOID = ctypes.c_void_p
_LPCWSTR = ctypes.c_wchar_p


class _OVERLAPPED(ctypes.Structure):
    """OVERLAPPED structure aligned with the Windows ABI."""

    _fields_ = [
        ("Internal", _LPVOID),
        ("InternalHigh", _LPVOID),
        ("Offset", _DWORD),
        ("OffsetHigh", _DWORD),
        ("hEvent", _HANDLE),
    ]


class _FILE_NOTIFY_INFORMATION(ctypes.Structure):
    """Header of an entry returned by ``ReadDirectoryChangesW``."""

    _fields_ = [
        ("NextEntryOffset", _DWORD),
        ("Action", _DWORD),
        ("FileNameLength", _DWORD),
        ("FileName", ctypes.c_wchar * 1),
    ]


def _load_kernel32() -> Any | None:
    """Load kernel32 with ``use_last_error``; return ``None`` if unavailable."""
    if os.name != "nt":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            _LPCWSTR, _DWORD, _DWORD, _LPVOID, _DWORD, _DWORD, _HANDLE
        ]
        kernel32.CreateFileW.restype = _HANDLE
        kernel32.ReadDirectoryChangesW.argtypes = [
            _HANDLE, _LPVOID, _DWORD, _BOOL, _DWORD,
            ctypes.POINTER(_DWORD), ctypes.POINTER(_OVERLAPPED), _LPVOID,
        ]
        kernel32.ReadDirectoryChangesW.restype = _BOOL
        kernel32.CancelIoEx.argtypes = [_HANDLE, ctypes.POINTER(_OVERLAPPED)]
        kernel32.CancelIoEx.restype = _BOOL
        kernel32.GetOverlappedResult.argtypes = [
            _HANDLE, ctypes.POINTER(_OVERLAPPED), ctypes.POINTER(_DWORD), _BOOL
        ]
        kernel32.GetOverlappedResult.restype = _BOOL
        kernel32.CreateEventW.argtypes = [_LPVOID, _BOOL, _BOOL, _LPCWSTR]
        kernel32.CreateEventW.restype = _HANDLE
        kernel32.ResetEvent.argtypes = [_HANDLE]
        kernel32.ResetEvent.restype = _BOOL
        kernel32.WaitForSingleObject.argtypes = [_HANDLE, _DWORD]
        kernel32.WaitForSingleObject.restype = _DWORD
        kernel32.CloseHandle.argtypes = [_HANDLE]
        kernel32.CloseHandle.restype = _BOOL
    except (AttributeError, OSError, ValueError):  # pragma: no cover - environment-dependent
        return None
    return kernel32


_kernel32 = _load_kernel32()
_HAS_NATIVE = _kernel32 is not None

# ``watchdog`` is optional. If unavailable, define an empty base
# so the handler declaration remains valid.
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - environment-dependent
    Observer = None

    class FileSystemEventHandler:
        """Empty base when ``watchdog`` is not installed."""


_HAS_WATCHDOG = Observer is not None

Action = str
"""Action associated with a finding: quarantined/detected/error (clean when there are no findings)."""


def available_backends() -> list[str]:
    """Return the usable backends, in order of preference.

    On Windows the native backend (dependency-free) is preferred, then
    ``watchdog`` if it can be imported, and finally polling, which is always
    available.
    """
    backends: list[str] = []
    if _HAS_NATIVE:
        backends.append("native")
    if _HAS_WATCHDOG:
        backends.append("watchdog")
    backends.append("polling")
    return backends


def _is_link(path: Path) -> bool:
    """Detect symlinks and, on Windows, junctions/reparse points."""
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    if os.name != "nt":
        return False
    try:
        attributes = ctypes.windll.kernel32.GetFileAttributesW(str(path))
    except (AttributeError, OSError):
        return False
    return attributes != -1 and bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


class _ChangeHandler(FileSystemEventHandler):
    """Translate watchdog events into candidate paths for analysis."""

    def __init__(
        self,
        callback: Callable[[Path], None],
        directories: Sequence[Path] = (),
        files: Sequence[Path] = (),
    ) -> None:
        self._callback = callback
        self._directories = tuple(directories)
        self._files = frozenset(str(path) for path in files)

    def _accept(self, raw_path: str) -> None:
        """Ignore directories and paths that do not belong to this watch."""
        path = Path(raw_path)
        if str(path) not in self._files and not any(
            path.is_relative_to(directory) for directory in self._directories
        ):
            return
        self._callback(path)

    def on_created(self, event: Any) -> None:
        if not event.is_directory:
            self._accept(event.src_path)

    def on_modified(self, event: Any) -> None:
        if not event.is_directory:
            self._accept(event.src_path)

    def on_moved(self, event: Any) -> None:
        if not event.is_directory:
            self._accept(event.dest_path)


class _NativeDirectoryWatcher(threading.Thread):
    """Watch a directory using ``ReadDirectoryChangesW`` with overlapped I/O.

    Each thread owns its own directory handle, manual-reset event, and
    64 KiB buffer. ``request_stop`` cancels the pending I/O with ``CancelIoEx``
    and the thread releases all handles in ``finally``.
    """

    def __init__(
        self,
        root: Path,
        callback: Callable[[Path], None],
        error_callback: Callable[[str, str], None],
        name: str,
    ) -> None:
        super().__init__(name=name, daemon=True)
        self._root = root
        self._callback = callback
        self._error_callback = error_callback
        self._stop_request = threading.Event()
        self._lock = threading.Lock()
        self._handle: int | None = None
        self._event: int | None = None
        self._io_pending = False
        self._buffer = ctypes.create_string_buffer(_NATIVE_BUFFER_SIZE)
        self._overlapped = _OVERLAPPED()
        self._bytes = _DWORD(0)

    def request_stop(self) -> None:
        """Request cancellation of the pending read without blocking."""
        self._stop_request.set()
        with self._lock:
            handle = self._handle
            if handle is not None and handle != _INVALID_HANDLE_VALUE and _kernel32:
                try:
                    _kernel32.CancelIoEx(handle, ctypes.byref(self._overlapped))
                except (OSError, ValueError):  # pragma: no cover - handle already closed
                    pass

    def run(self) -> None:
        """Open the directory, publish changes, and always close the handles."""
        handle = None
        event = None
        try:
            if self._stop_request.is_set() or _kernel32 is None:
                return
            handle = _kernel32.CreateFileW(
                str(self._root),
                _FILE_LIST_DIRECTORY,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
                None,
                _OPEN_EXISTING,
                _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OVERLAPPED,
                None,
            )
            if handle is None or handle == _INVALID_HANDLE_VALUE:
                self._error(f"could not open the directory ({ctypes.get_last_error()})")
                return
            event = _kernel32.CreateEventW(None, True, False, None)
            if not event or event == _INVALID_HANDLE_VALUE:
                self._error("could not create the overlapped I/O event")
                return
            with self._lock:
                self._handle = handle
                self._event = event
                self._overlapped.hEvent = event
            self._watch(handle, event)
        except Exception as exc:  # noqa: BLE001 - an I/O error must not bring down the monitor
            self._error(f"unexpected error: {exc}")
        finally:
            self._close(handle, event)

    def _watch(self, handle: int, event: int) -> None:
        """Chain overlapped reads until a stop is requested."""
        if _kernel32 is None:
            self._error("native backend unavailable")
            return
        buffer = ctypes.cast(self._buffer, _LPVOID)
        while True:
            # The lock ensures ``request_stop`` cancels after the read.
            with self._lock:
                if self._stop_request.is_set():
                    break
                _kernel32.ResetEvent(event)
                self._bytes.value = 0
                started = _kernel32.ReadDirectoryChangesW(
                    handle,
                    buffer,
                    _NATIVE_BUFFER_SIZE,
                    True,
                    _NOTIFY_FILTER,
                    ctypes.byref(self._bytes),
                    ctypes.byref(self._overlapped),
                    None,
                )
                self._io_pending = bool(started)
            if not started:
                error = ctypes.get_last_error()
                if not self._stop_request.is_set() and error != _ERROR_OPERATION_ABORTED:
                    self._error(f"ReadDirectoryChangesW failed ({error})")
                break
            while not self._stop_request.is_set():
                wait = _kernel32.WaitForSingleObject(event, _NATIVE_WAIT_MS)
                if wait == _WAIT_OBJECT_0:
                    break
                if wait == _WAIT_FAILED:
                    self._error(f"WaitForSingleObject failed ({ctypes.get_last_error()})")
                    return
            # CancelIoEx has already been requested on stop: the operation ends
            # with ERROR_OPERATION_ABORTED, which is treated as a normal exit.
            completed = _kernel32.GetOverlappedResult(
                handle, ctypes.byref(self._overlapped), ctypes.byref(self._bytes), True
            )
            self._io_pending = False
            if not completed:
                error = ctypes.get_last_error()
                if error == _ERROR_OPERATION_ABORTED or self._stop_request.is_set():
                    break
                if error == _ERROR_INSUFFICIENT_BUFFER:
                    self._error("event buffer overflowed; resuming monitoring")
                    continue
                self._error(f"GetOverlappedResult failed ({error})")
                break
            if self._stop_request.is_set():
                break
            if self._bytes.value:
                self._parse_events(self._bytes.value)

    def _parse_events(self, size: int) -> None:
        """Convert buffer entries into paths and publish them to the queue."""
        offset = 0
        limit = min(size, _NATIVE_BUFFER_SIZE)
        char_size = ctypes.sizeof(ctypes.c_wchar)
        while offset < limit:
            try:
                entry = ctypes.cast(
                    ctypes.byref(self._buffer, offset),
                    ctypes.POINTER(_FILE_NOTIFY_INFORMATION),
                ).contents
                if entry.Action in _WATCHED_ACTIONS and entry.FileNameLength:
                    count = entry.FileNameLength // char_size
                    name = ctypes.wstring_at(
                        ctypes.addressof(entry) + _FILE_NOTIFY_INFORMATION.FileName.offset,
                        count,
                    )
                    candidate = self._root / name
                    if self._is_safe(candidate):
                        self._callback(candidate)
            except (ValueError, OSError) as exc:  # pragma: no cover - corrupt buffer
                self._error(f"invalid event: {exc}")
                break
            if not entry.NextEntryOffset:
                break
            offset += entry.NextEntryOffset

    def _is_safe(self, path: Path) -> bool:
        """Discard paths outside the root or that cross reparse points."""
        try:
            relative = path.relative_to(self._root)
        except ValueError:
            return False
        current = self._root
        for part in relative.parts[:-1]:
            current = current / part
            if _is_link(current):
                return False
        return not _is_link(path)

    def _close(self, handle: int | None, event: int | None) -> None:
        """Cancel pending I/O, drain the result, and close the handles."""
        with self._lock:
            self._handle = None
            self._event = None
            self._overlapped.hEvent = None
        if handle is None or handle == _INVALID_HANDLE_VALUE or _kernel32 is None:
            return
        try:
            _kernel32.CancelIoEx(handle, ctypes.byref(self._overlapped))
            if event and self._io_pending:
                _kernel32.WaitForSingleObject(event, _NATIVE_WAIT_MS)
                _kernel32.GetOverlappedResult(
                    handle, ctypes.byref(self._overlapped), ctypes.byref(self._bytes), False
                )
        except (OSError, ValueError):  # pragma: no cover - handle already closed
            pass
        for handle_to_close in (event, handle):
            if handle_to_close and handle_to_close != _INVALID_HANDLE_VALUE:
                try:
                    _kernel32.CloseHandle(handle_to_close)
                except (OSError, ValueError):  # pragma: no cover - handle already closed
                    pass

    def _error(self, message: str) -> None:
        """Report the problem through the monitor's logger."""
        self._error_callback(str(self._root), f"native: {message}")


class RealtimeMonitor:
    """Monitor paths, analyze changes, and quarantine findings."""

    ACTION_QUARANTINED = "quarantined"
    ACTION_DETECTED = "detected"
    ACTION_CLEAN = "clean"
    ACTION_ERROR = "error"

    def __init__(
        self,
        paths: Sequence[str | Path],
        signatures: SignatureDatabase | None = None,
        config: ScanConfig | None = None,
        quarantine: Quarantine | None = None,
        logger: AuditLogger | None = None,
        allowlist: AllowList | None = None,
        on_finding: Callable[[Finding, str], None] | None = None,
        poll_interval: float = 2.0,
        grace_period: float = 0.5,
        backend: str | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        if grace_period < 0:
            raise ValueError("grace_period cannot be negative")
        backends = available_backends()
        if backend is not None and backend not in backends:
            raise ValueError(
                f"backend {backend!r} unavailable; valid options: {', '.join(backends)}"
            )

        self.paths = tuple(Path(path).absolute() for path in paths)
        self.config = config or ScanConfig()
        self.signatures = signatures or SignatureDatabase.empty()
        self.quarantine = quarantine
        self.logger = logger
        self.allowlist = allowlist
        self.on_finding = on_finding
        self.poll_interval = float(poll_interval)
        self.grace_period = float(grace_period)
        self._backend = backend if backend is not None else backends[0]

        # A single scan thread, no link following, and hashing always enabled.
        self.scan_config: ScanConfig = replace(
            self.config, hash_all=True, follow_symlinks=False, jobs=1
        )
        self.scan_config.validate()
        self.scanner = Scanner(
            self.signatures, self.scan_config, yara=None, allowlist=allowlist
        )

        self._excluded = frozenset(str(item).lower() for item in self.config.exclude_dirs)
        self._queue: queue.Queue[str] = queue.Queue()
        self._pending: dict[str, float] = {}
        self._in_progress: set[str] = set()
        self._snapshot: dict[str, tuple[int, int]] = {}
        self._last_poll = 0.0
        self._poll_enabled = self._backend == "polling"
        self._stop_event = threading.Event()
        self._state_lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._observer: Any = None
        self._native_watchers: list[_NativeDirectoryWatcher] = []

    @staticmethod
    def available_backends() -> list[str]:
        """Method alias for :func:`available_backends`."""
        return available_backends()

    @property
    def backend(self) -> str:
        """Selected backend (``native``, ``watchdog``, or ``polling``)."""
        return self._backend

    @property
    def is_alive(self) -> bool:
        """Whether the worker thread is still alive."""
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def start(self) -> None:
        """Start the observer and worker thread (idempotent)."""
        with self._state_lock:
            if self.is_alive:
                return
            self._stop_event.clear()
            if self._backend == "watchdog" and Observer is not None:
                self._start_observer()
            elif self._backend == "native" and _HAS_NATIVE:
                self._start_native()
                # The native backend only polls loose files; directories are
                # handled by ReadDirectoryChangesW.
                self._snapshot = self._build_snapshot()
                self._last_poll = time.monotonic()
            else:
                # The baseline is taken here so files created right after
                # ``start()`` returns are not missed.
                self._snapshot = self._build_snapshot()
                self._last_poll = time.monotonic()
            self._thread = threading.Thread(
                target=self._worker, name="sentinel-realtime", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop observers and the worker thread. Safe to call multiple times."""
        with self._state_lock:
            self._stop_event.set()
            thread = self._thread
            observer = self._observer
            watchers = list(self._native_watchers)
            self._thread = None
            self._observer = None
            self._native_watchers.clear()
            self._pending.clear()
        self._queue.put("")  # Wake the thread if it is waiting on the queue.
        for watcher in watchers:
            watcher.request_stop()
        deadline = time.monotonic() + max(0.0, timeout)
        if observer is not None:
            try:
                observer.stop()
            except Exception as exc:  # noqa: BLE001 - a dead observer must not prevent shutdown
                self._emit_error("observer", f"stop: {exc}")
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for watcher in watchers:
            watcher.join(timeout=max(0.0, deadline - time.monotonic()))
        if observer is not None:
            try:
                observer.join(timeout=max(0.0, deadline - time.monotonic()))
            except (RuntimeError, OSError, ValueError):
                pass

    def process_path(self, path: str | Path) -> tuple[ScanResult, str]:
        """Analyze a file, quarantine it if needed, and return ``(result, action)``.

        The action is ``"quarantined"`` if it was isolated, ``"detected"`` if
        there are findings but no quarantine, ``"error"`` if processing failed,
        and ``"clean"`` when there are no findings (or the path is ignored).
        """
        target = Path(path)
        result = ScanResult(roots=[str(target)])
        action = self.ACTION_CLEAN
        try:
            if not self._is_watchable(target):
                return result, action

            result = self.scanner.scan([target])
            if result.errors and not result.findings:
                action = self.ACTION_ERROR
                for error in result.errors:
                    self._emit_error(str(target), error.get("error", "analysis error"))
                return result, action
            if not result.findings:
                return result, action

            rule_ids = sorted({finding.rule_id for finding in result.findings})
            if self.quarantine is not None:
                digest = next((item.sha256 for item in result.findings if item.sha256), "")
                entry_id = self.quarantine.add(
                    target, reason=", ".join(rule_ids), sha256=digest
                )
                for finding in result.findings:
                    finding.quarantined = True
                    finding.quarantine_id = entry_id
                action = self.ACTION_QUARANTINED
                self._emit_quarantine(str(target), entry_id, digest, rule_ids)
            else:
                action = self.ACTION_DETECTED

            for finding in result.findings:
                self._emit_detection(finding, action)
            for finding in result.findings:
                self._notify(finding, action)
        except Exception as exc:  # noqa: BLE001 - the monitor must never die because of a single file
            action = self.ACTION_ERROR
            self._emit_error(str(target), str(exc))
            for finding in result.findings:
                self._notify(finding, action)
        return result, action

    def _start_observer(self) -> None:
        """Configure watchdog for directories and individual files."""
        directories = [
            item for item in self.paths if self._is_watchable(item, require_file=False)
        ]
        files = [item for item in self.paths if self._is_watchable(item)]
        if not directories and not files:
            return
        handler = _ChangeHandler(self._enqueue, directories, files)
        observer = Observer()
        for directory in directories:
            observer.schedule(handler, str(directory), recursive=True)
        for parent in {str(item.parent) for item in files}:
            observer.schedule(handler, parent, recursive=False)
        observer.start()
        self._observer = observer

    def _start_native(self) -> None:
        """Create one native watcher per directory, without following links."""
        directories = [
            item
            for item in self.paths
            if item.is_dir() and self._is_watchable(item, require_file=False)
        ]
        # A directory inside another is already covered by the parent root.
        selected: list[Path] = []
        for directory in sorted(set(directories), key=lambda item: len(item.parts)):
            if not any(directory.is_relative_to(other) for other in selected):
                selected.append(directory)
        self._poll_enabled = any(
            self._is_watchable(item) for item in self.paths if item.is_file()
        )
        for index, directory in enumerate(selected):
            watcher = _NativeDirectoryWatcher(
                directory,
                self._enqueue,
                self._emit_error,
                f"sentinel-native-{index}",
            )
            watcher.start()
            self._native_watchers.append(watcher)

    def _worker(self) -> None:
        """Consume the queue and process paths once the grace period elapses."""
        while not self._stop_event.is_set():
            now = time.monotonic()
            if self._poll_enabled and now - self._last_poll >= self.poll_interval:
                self._poll_once()
                self._last_poll = now
            try:
                self._queue.get(timeout=self._next_timeout())
            except queue.Empty:
                pass
            self._process_due()
        self._pending.clear()

    def _next_timeout(self) -> float:
        """Wait at most until the next deadline or poll."""
        timeout = self.poll_interval if self._poll_enabled else 0.25
        if self._pending:
            remaining = min(self._pending.values()) - time.monotonic()
            timeout = min(timeout, max(0.01, remaining))
        return max(0.01, timeout)

    def _process_due(self) -> None:
        """Extract due paths, marking them as in progress."""
        now = time.monotonic()
        with self._state_lock:
            due = [
                key
                for key, deadline in self._pending.items()
                if deadline <= now and key not in self._in_progress
            ]
            for key in due:
                del self._pending[key]
                self._in_progress.add(key)
        for key in due:
            try:
                self.process_path(key)
            finally:
                with self._state_lock:
                    self._in_progress.discard(key)

    def _enqueue(self, path: str | Path) -> None:
        """Schedule a path after the grace period, merging repeated events."""
        if self._stop_event.is_set():
            return
        candidate = Path(path)
        if not self._is_watchable(candidate):
            return
        if self.allowlist is not None and self.allowlist.allows_path(candidate):
            return
        key = str(candidate)
        with self._state_lock:
            if key in self._in_progress:
                return
            self._pending[key] = time.monotonic() + self.grace_period
        self._queue.put(key)

    def _build_snapshot(self) -> dict[str, tuple[int, int]]:
        """Record ``(size, mtime)`` of the currently watched files."""
        snapshot: dict[str, tuple[int, int]] = {}
        for path in self._iter_watched_files():
            try:
                stat = path.stat()
            except OSError:
                continue
            snapshot[str(path)] = (stat.st_size, stat.st_mtime_ns)
        return snapshot

    def _poll_once(self) -> None:
        """Detect additions and changes by comparing the current state with the previous one."""
        current = self._build_snapshot()
        for key, signature in current.items():
            if self._snapshot.get(key) != signature:
                self._enqueue(key)
        self._snapshot = current

    def _iter_watched_files(self) -> Iterator[Path]:
        """Walk watched paths without following links or excluded directories."""
        for root in self.paths:
            if not self._is_watchable(root, require_file=False):
                continue
            if root.is_file():
                yield root
                continue
            if self._backend == "native":
                # Directories are already watched by ReadDirectoryChangesW.
                continue
            for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
                base = Path(current)
                dirs[:] = [
                    name
                    for name in dirs
                    if not self._is_excluded(base / name) and not _is_link(base / name)
                ]
                for name in files:
                    path = base / name
                    if not self._is_watchable(path):
                        continue
                    if self.allowlist is not None and self.allowlist.allows_path(path):
                        continue
                    yield path

    def _is_watchable(self, path: Path, *, require_file: bool = True) -> bool:
        """Check existence, links, exclusions, and the quarantine directory."""
        try:
            exists = path.is_file() if require_file else path.is_dir() or path.is_file()
            if not exists or _is_link(path) or self._is_excluded(path):
                return False
        except OSError:
            return False
        if self.quarantine is None:
            return True
        directory = normalize_path(self.quarantine.directory)
        candidate = normalize_path(path)
        return not candidate.startswith(directory + os.sep)

    def _is_excluded(self, path: Path) -> bool:
        """Discard files under ``config.exclude_dirs`` (case-insensitive comparison)."""
        try:
            parts = path.resolve().parts
        except OSError:
            parts = path.parts
        return any(part.lower() in self._excluded for part in parts)

    def _emit_detection(self, finding: Finding, action: Action) -> None:
        if self.logger is None:
            return
        self.logger.emit(
            "realtime.detection",
            path=finding.path,
            rule_id=finding.rule_id,
            detection=finding.detection.value,
            severity=finding.severity.value,
            sha256=finding.sha256,
            action=action,
        )

    def _emit_quarantine(
        self, path: str, entry_id: str, digest: str, rule_ids: list[str]
    ) -> None:
        if self.logger is None:
            return
        self.logger.emit(
            "realtime.quarantine",
            path=path,
            quarantine_id=entry_id,
            sha256=digest,
            rule_ids=rule_ids,
            action=self.ACTION_QUARANTINED,
        )

    def _emit_error(self, path: str, message: str) -> None:
        if self.logger is not None:
            self.logger.emit("realtime.error", path=path, error=message)

    def _notify(self, finding: Finding, action: Action) -> None:
        if self.on_finding is None:
            return
        try:
            self.on_finding(finding, action)
        except Exception as exc:  # noqa: BLE001 - a broken callback must not stop the monitor
            self._emit_error(finding.path, f"callback: {exc}")


__all__ = ["RealtimeMonitor", "available_backends"]
