"""Monitorización en tiempo real de archivos nuevos o modificados.

La clase :class:`RealtimeMonitor` vigila directorios (recursivamente) y
archivos concretos. En Windows se usa un backend nativo basado en ``ctypes``
y ``ReadDirectoryChangesW``; después se prueba ``watchdog`` y, como último
recurso, un sondeo con ``os.stat`` que no requiere dependencias externas.
Todo el análisis se realiza en un único hilo de trabajo que consume una cola
de rutas pendientes.
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

# Constantes y estructuras del backend nativo de Windows (ctypes puro).
# Se declaran en todos los sistemas para que el módulo sea importable en
# plataformas donde ``ctypes.WinDLL`` no existe.
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
    """Estructura OVERLAPPED alineada con el ABI de Windows."""

    _fields_ = [
        ("Internal", _LPVOID),
        ("InternalHigh", _LPVOID),
        ("Offset", _DWORD),
        ("OffsetHigh", _DWORD),
        ("hEvent", _HANDLE),
    ]


class _FILE_NOTIFY_INFORMATION(ctypes.Structure):
    """Cabecera de una entrada devuelta por ``ReadDirectoryChangesW``."""

    _fields_ = [
        ("NextEntryOffset", _DWORD),
        ("Action", _DWORD),
        ("FileNameLength", _DWORD),
        ("FileName", ctypes.c_wchar * 1),
    ]


def _load_kernel32() -> Any | None:
    """Carga kernel32 con ``use_last_error``; devuelve ``None`` si no está disponible."""
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
    except (AttributeError, OSError, ValueError):  # pragma: no cover - depende del entorno
        return None
    return kernel32


_kernel32 = _load_kernel32()
_HAS_NATIVE = _kernel32 is not None

# ``watchdog`` es opcional. Si no está disponible se define una base vacía
# para que la declaración del manejador siga siendo válida.
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - depende del entorno
    Observer = None

    class FileSystemEventHandler:
        """Base vacía cuando ``watchdog`` no está instalado."""


_HAS_WATCHDOG = Observer is not None

Action = str
"""Acción asociada a un hallazgo: quarantined/detected/error (clean si no hay hallazgos)."""


def available_backends() -> list[str]:
    """Devuelve los backends utilizables, ordenados por preferencia.

    En Windows se prefiere el backend nativo (sin dependencias), después
    ``watchdog`` si se puede importar y finalmente el sondeo, siempre disponible.
    """
    backends: list[str] = []
    if _HAS_NATIVE:
        backends.append("native")
    if _HAS_WATCHDOG:
        backends.append("watchdog")
    backends.append("polling")
    return backends


def _is_link(path: Path) -> bool:
    """Detecta symlinks y, en Windows, junctions/reparse points."""
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
    """Traduce los eventos de watchdog en rutas candidatas a análisis."""

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
        """Ignora directorios y rutas que no pertenecen a esta vigilancia."""
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
    """Vigila un directorio con ``ReadDirectoryChangesW`` sobre E/S solapada.

    Cada hilo posee su propio handle de directorio, evento manual y buffer de
    64 KiB. ``request_stop`` cancela la E/S pendiente con ``CancelIoEx`` y el
    hilo libera todos los handles en ``finally``.
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
        """Pide la cancelación de la lectura pendiente sin bloquear."""
        self._stop_request.set()
        with self._lock:
            handle = self._handle
            if handle is not None and handle != _INVALID_HANDLE_VALUE and _kernel32:
                try:
                    _kernel32.CancelIoEx(handle, ctypes.byref(self._overlapped))
                except (OSError, ValueError):  # pragma: no cover - handle ya cerrado
                    pass

    def run(self) -> None:
        """Abre el directorio, publica cambios y cierra los handles siempre."""
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
                self._error(f"no se pudo abrir el directorio ({ctypes.get_last_error()})")
                return
            event = _kernel32.CreateEventW(None, True, False, None)
            if not event or event == _INVALID_HANDLE_VALUE:
                self._error("no se pudo crear el evento de E/S solapada")
                return
            with self._lock:
                self._handle = handle
                self._event = event
                self._overlapped.hEvent = event
            self._watch(handle, event)
        except Exception as exc:  # noqa: BLE001 - un error de E/S no debe tumbar el monitor
            self._error(f"error inesperado: {exc}")
        finally:
            self._close(handle, event)

    def _watch(self, handle: int, event: int) -> None:
        """Encadena lecturas solapadas hasta que se solicite la parada."""
        assert _kernel32 is not None
        buffer = ctypes.cast(self._buffer, _LPVOID)
        while True:
            # El cerrojo garantiza que ``request_stop`` cancele después de la lectura.
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
                    self._error(f"ReadDirectoryChangesW falló ({error})")
                break
            while not self._stop_request.is_set():
                wait = _kernel32.WaitForSingleObject(event, _NATIVE_WAIT_MS)
                if wait == _WAIT_OBJECT_0:
                    break
                if wait == _WAIT_FAILED:
                    self._error(f"WaitForSingleObject falló ({ctypes.get_last_error()})")
                    return
            # CancelIoEx ya fue solicitado si hay parada: la operación termina con
            # ERROR_OPERATION_ABORTED, que se trata como una salida normal.
            completed = _kernel32.GetOverlappedResult(
                handle, ctypes.byref(self._overlapped), ctypes.byref(self._bytes), True
            )
            self._io_pending = False
            if not completed:
                error = ctypes.get_last_error()
                if error == _ERROR_OPERATION_ABORTED or self._stop_request.is_set():
                    break
                if error == _ERROR_INSUFFICIENT_BUFFER:
                    self._error("buffer de eventos desbordado; se reanuda la vigilancia")
                    continue
                self._error(f"GetOverlappedResult falló ({error})")
                break
            if self._stop_request.is_set():
                break
            if self._bytes.value:
                self._parse_events(self._bytes.value)

    def _parse_events(self, size: int) -> None:
        """Convierte las entradas del buffer en rutas y las publica en la cola."""
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
            except (ValueError, OSError) as exc:  # pragma: no cover - buffer corrupto
                self._error(f"evento no válido: {exc}")
                break
            if not entry.NextEntryOffset:
                break
            offset += entry.NextEntryOffset

    def _is_safe(self, path: Path) -> bool:
        """Descarta rutas fuera de la raíz o que cruzan reparse points."""
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
        """Cancela la E/S pendiente, drena el resultado y cierra los handles."""
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
        except (OSError, ValueError):  # pragma: no cover - handle ya cerrado
            pass
        for handle_to_close in (event, handle):
            if handle_to_close and handle_to_close != _INVALID_HANDLE_VALUE:
                try:
                    _kernel32.CloseHandle(handle_to_close)
                except (OSError, ValueError):  # pragma: no cover - handle ya cerrado
                    pass

    def _error(self, message: str) -> None:
        """Informa del problema a través del registrador del monitor."""
        self._error_callback(str(self._root), f"native: {message}")


class RealtimeMonitor:
    """Vigila rutas, analiza cambios y envía a cuarentena los hallazgos."""

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
            raise ValueError("poll_interval debe ser positivo")
        if grace_period < 0:
            raise ValueError("grace_period no puede ser negativo")
        backends = available_backends()
        if backend is not None and backend not in backends:
            raise ValueError(
                f"backend {backend!r} no disponible; opciones válidas: {', '.join(backends)}"
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

        # Un único hilo de escaneo, sin seguimiento de enlaces y con hash siempre.
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
        """Alias de método para :func:`available_backends`."""
        return available_backends()

    @property
    def backend(self) -> str:
        """Backend seleccionado (``native``, ``watchdog`` o ``polling``)."""
        return self._backend

    @property
    def is_alive(self) -> bool:
        """Indica si el hilo de trabajo sigue activo."""
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def start(self) -> None:
        """Arranca el observador y el hilo de trabajo (idempotente)."""
        with self._state_lock:
            if self.is_alive:
                return
            self._stop_event.clear()
            if self._backend == "watchdog" and Observer is not None:
                self._start_observer()
            elif self._backend == "native" and _HAS_NATIVE:
                self._start_native()
                # El backend nativo solo sondea los archivos sueltos; los
                # directorios son gestionados por ReadDirectoryChangesW.
                self._snapshot = self._build_snapshot()
                self._last_poll = time.monotonic()
            else:
                # La línea base se toma aquí para no perder archivos creados
                # justo después de que ``start()`` devuelva el control.
                self._snapshot = self._build_snapshot()
                self._last_poll = time.monotonic()
            self._thread = threading.Thread(
                target=self._worker, name="sentinel-realtime", daemon=True
            )
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Detiene observadores y hilo de trabajo. Seguro llamarlo varias veces."""
        with self._state_lock:
            self._stop_event.set()
            thread = self._thread
            observer = self._observer
            watchers = list(self._native_watchers)
            self._thread = None
            self._observer = None
            self._native_watchers.clear()
            self._pending.clear()
        self._queue.put("")  # Despierta al hilo si está esperando en la cola.
        for watcher in watchers:
            watcher.request_stop()
        deadline = time.monotonic() + max(0.0, timeout)
        if observer is not None:
            try:
                observer.stop()
            except Exception as exc:  # noqa: BLE001 - un observer muerto no debe impedir parar
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
        """Analiza un archivo, lo aísla si procede y devuelve ``(resultado, acción)``.

        La acción es ``"quarantined"`` si se aisló, ``"detected"`` si hay
        hallazgos pero no hay cuarentena, ``"error"`` si falló el proceso y
        ``"clean"`` cuando no hay hallazgos (o la ruta se ignora).
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
                    self._emit_error(str(target), error.get("error", "error de análisis"))
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
        except Exception as exc:  # noqa: BLE001 - el monitor nunca debe morir por un archivo
            action = self.ACTION_ERROR
            self._emit_error(str(target), str(exc))
            for finding in result.findings:
                self._notify(finding, action)
        return result, action

    def _start_observer(self) -> None:
        """Configura watchdog para directorios y archivos concretos."""
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
        """Crea un vigilante nativo por directorio, sin seguir enlaces."""
        directories = [
            item
            for item in self.paths
            if item.is_dir() and self._is_watchable(item, require_file=False)
        ]
        # Un directorio contenido en otro ya queda cubierto por la raíz mayor.
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
        """Consume la cola y procesa las rutas cuando pasa el grace period."""
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
        """Espera como máximo hasta el próximo vencimiento o sondeo."""
        timeout = self.poll_interval if self._poll_enabled else 0.25
        if self._pending:
            remaining = min(self._pending.values()) - time.monotonic()
            timeout = min(timeout, max(0.01, remaining))
        return max(0.01, timeout)

    def _process_due(self) -> None:
        """Extrae las rutas listas, marcándolas como en proceso."""
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
        """Programa una ruta tras el grace period, fusionando eventos repetidos."""
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
        """Guarda ``(tamaño, mtime)`` de los archivos vigilados ahora mismo."""
        snapshot: dict[str, tuple[int, int]] = {}
        for path in self._iter_watched_files():
            try:
                stat = path.stat()
            except OSError:
                continue
            snapshot[str(path)] = (stat.st_size, stat.st_mtime_ns)
        return snapshot

    def _poll_once(self) -> None:
        """Detecta altas y cambios comparando el estado actual con el anterior."""
        current = self._build_snapshot()
        for key, signature in current.items():
            if self._snapshot.get(key) != signature:
                self._enqueue(key)
        self._snapshot = current

    def _iter_watched_files(self) -> Iterator[Path]:
        """Recorre las rutas vigiladas sin seguir enlaces ni directorios excluidos."""
        for root in self.paths:
            if not self._is_watchable(root, require_file=False):
                continue
            if root.is_file():
                yield root
                continue
            if self._backend == "native":
                # Los directorios ya los vigila ReadDirectoryChangesW.
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
        """Comprueba existencia, enlaces, exclusiones y directorio de cuarentena."""
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
        """Descarta archivos bajo ``config.exclude_dirs`` (comparación insensible)."""
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
        except Exception as exc:  # noqa: BLE001 - un callback defectuoso no detiene el monitor
            self._emit_error(finding.path, f"callback: {exc}")


__all__ = ["RealtimeMonitor", "available_backends"]
