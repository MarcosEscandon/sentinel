"""Windows service for real-time protection.

The service reads ``<home>/service.json`` and delegates monitoring to
:class:`~sentinel.realtime.RealtimeMonitor`. Installing it requires
``pywin32`` and administrator privileges.

Modes:

* installed: ``pythonservice.exe`` (or the frozen executable) hosts
  ``SentinelService`` and responds to SCM controls;
* foreground: ``sentinel service run`` allows debugging without installing
  anything.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from .security_fs import secure_write_text

SERVICE_NAME = "SentinelRealtime"
DISPLAY_NAME = "Sentinel Real-time Protection"
DESCRIPTION = "Sentinel real-time protection (signatures + heuristics)."
CONFIG_NAME = "service.json"

DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))
DEFAULT_SIGNATURES = Path(__file__).parent / "data" / "signatures.json"
# Pointer persisted at installation time: the SCM runs the service as
# LocalSystem, so Path.home() no longer points to the user who installed it.
# Without this, SvcDoRun looked for service.json in the LocalSystem profile.
SERVICE_HOME_POINTER = (
    Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "sentinel" / "service_home.txt"
)

STARTUP_MODES = ("auto", "manual", "disabled")


class ServiceUnavailable(Exception):
    """pywin32 or Windows is unavailable."""


def service_available() -> bool:
    """Whether the Windows service can be managed."""
    if os.name != "nt":
        return False
    return find_spec("win32service") is not None and find_spec("win32serviceutil") is not None


def config_path(home: str | Path) -> Path:
    return Path(home) / CONFIG_NAME


def save_service_home(home: str | Path) -> None:
    """Persist the ``--home`` chosen when the service was installed."""
    if os.name != "nt":
        return
    SERVICE_HOME_POINTER.parent.mkdir(parents=True, exist_ok=True)
    secure_write_text(SERVICE_HOME_POINTER, str(Path(home).resolve()))


def load_service_home() -> Path:
    """Retrieve the home saved at installation; if there is no pointer, use DEFAULT_HOME."""
    if os.name != "nt":
        return DEFAULT_HOME
    try:
        value = SERVICE_HOME_POINTER.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return DEFAULT_HOME
    return Path(value) if value else DEFAULT_HOME


def clear_service_home() -> None:
    """Remove the pointer when the service is uninstalled."""
    if os.name != "nt":
        return
    try:
        SERVICE_HOME_POINTER.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        pass


def save_config(
    home: str | Path,
    *,
    paths: list[str],
    signatures: str | Path | None = None,
    config_file: str | Path | None = None,
    poll_interval: float = 2.0,
    public_key: str | Path | None = None,
) -> Path:
    """Save the configuration the service will use at startup."""
    if not paths:
        raise ValueError("The service needs at least one path to monitor")
    if poll_interval <= 0:
        raise ValueError("poll_interval must be positive")
    payload: dict[str, Any] = {
        "version": 1,
        "paths": [str(path) for path in paths],
        "signatures": str(signatures or DEFAULT_SIGNATURES),
        "config_file": str(config_file) if config_file else "",
        "poll_interval": poll_interval,
        "public_key": str(public_key) if public_key else "",
    }
    destination = config_path(home)
    destination.parent.mkdir(parents=True, exist_ok=True)
    secure_write_text(destination, json.dumps(payload, indent=2, ensure_ascii=False))
    return destination


def load_config(home: str | Path) -> dict[str, Any]:
    """Load the service configuration."""
    path = config_path(home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ServiceUnavailable(f"No service configuration found at {path}") from exc
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"Invalid service configuration at {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("paths"), list):
        raise TypeError(f"Invalid service configuration at {path}")
    return payload


def build_monitor(home: str | Path) -> Any:
    """Build the monitor from the saved configuration."""
    try:
        from . import trust
        from .config import ScanConfig
        from .core.allowlist import AllowList
        from .core.logging import AuditLogger
        from .core.quarantine import Quarantine
        from .realtime import RealtimeMonitor
    except ImportError as exc:  # pragma: no cover - depends on optional extras
        raise ServiceUnavailable(f"Could not start real-time protection: {exc}") from exc

    root = Path(home)
    config_data = load_config(root)
    scan_config = (
        ScanConfig.from_file(config_data["config_file"])
        if config_data.get("config_file")
        else ScanConfig()
    )
    configured_key = str(config_data.get("public_key") or "") or None
    signatures = trust.load_database(
        config_data["signatures"],
        home=root,
        public_key=configured_key,
        require_signature=True,
    )
    return RealtimeMonitor(
        paths=config_data["paths"],
        signatures=signatures,
        config=scan_config,
        quarantine=Quarantine(root / "quarantine"),
        logger=AuditLogger(root / "audit.jsonl"),
        allowlist=AllowList.for_self([root, Path(__file__).parent.parent]),
        poll_interval=float(config_data.get("poll_interval", 2.0)),
    )


def run_foreground(home: str | Path) -> int:
    """Run the monitor in the foreground (Ctrl+C to stop)."""
    monitor = build_monitor(home)
    monitor.start()
    print("Real-time protection active. Press Ctrl+C to stop.")
    try:
        while getattr(monitor, "is_alive", True):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping real-time protection...")
    finally:
        monitor.stop()
    return 0


def _require_service() -> Any:
    if not service_available():
        raise ServiceUnavailable(
            "Windows and pywin32 are required. Install with: pip install -e '.[service]'"
        )
    import win32service
    import win32serviceutil

    return win32service, win32serviceutil


def _startup_constant(startup: str) -> int:
    if startup not in STARTUP_MODES:
        raise ValueError(f"startup must be one of {', '.join(STARTUP_MODES)}")
    win32service, _ = _require_service()
    return {
        "auto": win32service.SERVICE_AUTO_START,
        "manual": win32service.SERVICE_DEMAND_START,
        "disabled": win32service.SERVICE_DISABLED,
    }[startup]


def _python_class() -> str | None:
    """In a frozen executable there is no importable module: the dispatcher lives in main()."""
    return None if getattr(sys, "frozen", False) else f"{__name__}.SentinelService"


def install(home: str | Path, *, startup: str = "auto") -> str:
    """Install the service (requires administrator privileges)."""
    _, util = _require_service()
    start_type = _startup_constant(startup)
    kwargs: dict[str, Any] = {
        "startType": start_type,
        "description": DESCRIPTION,
    }
    if getattr(sys, "frozen", False):
        kwargs["exeName"] = sys.executable
    util.InstallService(_python_class(), SERVICE_NAME, DISPLAY_NAME, **kwargs)
    save_service_home(home)
    return SERVICE_NAME


def remove() -> None:
    """Uninstall the service (requires administrator privileges)."""
    _, util = _require_service()
    util.RemoveService(SERVICE_NAME)
    clear_service_home()


def start(wait: int = 15) -> None:
    """Start the service and wait until it is running."""
    _, util = _require_service()
    util.StartService(SERVICE_NAME)
    if wait:
        import win32service

        util.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, wait)


def stop(wait: int = 15) -> None:
    """Stop the service."""
    _, util = _require_service()
    if wait:
        util.StopServiceWithDeps(SERVICE_NAME, waitSecs=wait)
    else:
        util.StopService(SERVICE_NAME)


def status() -> str:
    """Return the current service status."""
    win32service, util = _require_service()
    try:
        info = util.QueryServiceStatus(SERVICE_NAME)
    except Exception as exc:  # pywintypes.error not always importable in tests
        raise ServiceUnavailable(f"Could not query {SERVICE_NAME}: {exc}") from exc
    states = {
        win32service.SERVICE_STOPPED: "stopped",
        win32service.SERVICE_START_PENDING: "starting",
        win32service.SERVICE_STOP_PENDING: "stopping",
        win32service.SERVICE_RUNNING: "running",
        win32service.SERVICE_CONTINUE_PENDING: "continuing",
        win32service.SERVICE_PAUSE_PENDING: "pausing",
        win32service.SERVICE_PAUSED: "paused",
    }
    return states.get(info[1], f"unknown ({info[1]})")


def dispatch_frozen() -> bool:
    """Register the SCM dispatcher when the frozen executable starts without arguments."""
    if not getattr(sys, "frozen", False) or len(sys.argv) > 1:
        return False
    if not service_available():
        return False
    import servicemanager

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(SentinelService)
    servicemanager.StartServiceCtrlDispatcher()
    return True


# The class exists only when pywin32 is available.
SentinelService: Any = None
if service_available():  # pragma: no cover - environment-dependent
    import servicemanager
    import win32service
    from win32serviceutil import ServiceFramework

    class SentinelService(ServiceFramework):  # type: ignore[no-redef]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            # pywin32 >= 312 does not create StopEvent in ServiceFramework.
            self.StopEvent = threading.Event()
            self.monitor: Any = None

        def SvcDoRun(self) -> None:
            try:
                self.monitor = build_monitor(load_service_home())
                self.monitor.start()
                while not self.StopEvent.wait(1.0):
                    if not getattr(self.monitor, "is_alive", True):
                        break
            except Exception as exc:  # the SCM must receive the error, not a silent traceback
                servicemanager.LogErrorMsg(f"Sentinel: {exc}")
                raise

        def SvcStop(self) -> None:
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.StopEvent.set()
            if self.monitor is not None:
                self.monitor.stop()


__all__ = [
    "DESCRIPTION",
    "DISPLAY_NAME",
    "SERVICE_NAME",
    "SentinelService",
    "ServiceUnavailable",
    "build_monitor",
    "clear_service_home",
    "config_path",
    "dispatch_frozen",
    "install",
    "load_config",
    "load_service_home",
    "remove",
    "run_foreground",
    "save_config",
    "save_service_home",
    "service_available",
    "start",
    "status",
    "stop",
]
