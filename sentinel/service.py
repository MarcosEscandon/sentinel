"""Servicio de Windows para protección en tiempo real.

El servicio lee ``<home>/service.json`` y delega la vigilancia en
:class:`~sentinel.realtime.RealtimeMonitor`. Requiere ``pywin32`` y privilegios
de administrador para instalarse.

Modos:

* instalado: ``pythonservice.exe`` (o el exe congelado) hospeda
  ``SentinelService`` y responde a los controles del SCM;
* primer plano: ``sentinel service run`` permite depurar sin instalar nada.
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

SERVICE_NAME = "SentinelRealtime"
DISPLAY_NAME = "Sentinel Real-time Protection"
DESCRIPTION = "Protección en tiempo real de Sentinel (firmas + heurística)."
CONFIG_NAME = "service.json"

DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))
DEFAULT_SIGNATURES = Path(__file__).parent / "data" / "signatures.json"
# Puntero persistido al instalar: el SCM ejecuta el servicio como LocalSystem y
# Path.home() ya no apunta al usuario que instaló. Sin esto, SvcDoRun buscaba
# service.json en el perfil de LocalSystem.
SERVICE_HOME_POINTER = (
    Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "sentinel" / "service_home.txt"
)

STARTUP_MODES = ("auto", "manual", "disabled")


class ServiceUnavailable(Exception):
    """pywin32 o Windows no están disponibles."""


def service_available() -> bool:
    """Indica si se puede gestionar el servicio de Windows."""
    if os.name != "nt":
        return False
    return find_spec("win32service") is not None and find_spec("win32serviceutil") is not None


def config_path(home: str | Path) -> Path:
    return Path(home) / CONFIG_NAME


def save_service_home(home: str | Path) -> None:
    """Persiste el ``--home`` elegido al instalar el servicio."""
    if os.name != "nt":
        return
    SERVICE_HOME_POINTER.parent.mkdir(parents=True, exist_ok=True)
    SERVICE_HOME_POINTER.write_text(str(Path(home).resolve()), encoding="utf-8")


def load_service_home() -> Path:
    """Recupera el home guardado al instalar; si no hay puntero, usa DEFAULT_HOME."""
    if os.name != "nt":
        return DEFAULT_HOME
    try:
        value = SERVICE_HOME_POINTER.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return DEFAULT_HOME
    return Path(value) if value else DEFAULT_HOME


def clear_service_home() -> None:
    """Elimina el puntero al desinstalar el servicio."""
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
) -> Path:
    """Guarda la configuración que usará el servicio al arrancar."""
    if not paths:
        raise ValueError("El servicio necesita al menos una ruta que vigilar")
    if poll_interval <= 0:
        raise ValueError("poll_interval debe ser positivo")
    payload: dict[str, Any] = {
        "version": 1,
        "paths": [str(path) for path in paths],
        "signatures": str(signatures or DEFAULT_SIGNATURES),
        "config_file": str(config_file) if config_file else "",
        "poll_interval": poll_interval,
    }
    destination = config_path(home)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return destination


def load_config(home: str | Path) -> dict[str, Any]:
    """Carga la configuración del servicio."""
    path = config_path(home)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ServiceUnavailable(f"No hay configuración de servicio en {path}") from exc
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        raise ValueError(f"Configuración de servicio inválida en {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("paths"), list):
        raise TypeError(f"Configuración de servicio inválida en {path}")
    return payload


def build_monitor(home: str | Path) -> Any:
    """Construye el monitor a partir de la configuración guardada."""
    try:
        from .config import ScanConfig
        from .core.allowlist import AllowList
        from .core.logging import AuditLogger
        from .core.quarantine import Quarantine
        from .engine.signatures import SignatureDatabase
        from .realtime import RealtimeMonitor
    except ImportError as exc:  # pragma: no cover - depende de extras opcionales
        raise ServiceUnavailable(f"No se pudo iniciar la protección en tiempo real: {exc}") from exc

    root = Path(home)
    config_data = load_config(root)
    scan_config = (
        ScanConfig.from_file(config_data["config_file"])
        if config_data.get("config_file")
        else ScanConfig()
    )
    signatures = SignatureDatabase.load(config_data["signatures"])
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
    """Ejecuta el monitor en primer plano (Ctrl+C para detener)."""
    monitor = build_monitor(home)
    monitor.start()
    print("Protección en tiempo real activa. Ctrl+C para detener.")
    try:
        while getattr(monitor, "is_alive", True):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nDeteniendo la protección en tiempo real...")
    finally:
        monitor.stop()
    return 0


def _require_service() -> Any:
    if not service_available():
        raise ServiceUnavailable(
            "Se necesita Windows y pywin32. Instálalo con: pip install -e '.[service]'"
        )
    import win32service
    import win32serviceutil

    return win32service, win32serviceutil


def _startup_constant(startup: str) -> int:
    if startup not in STARTUP_MODES:
        raise ValueError(f"startup debe ser uno de {', '.join(STARTUP_MODES)}")
    win32service, _ = _require_service()
    return {
        "auto": win32service.SERVICE_AUTO_START,
        "manual": win32service.SERVICE_DEMAND_START,
        "disabled": win32service.SERVICE_DISABLED,
    }[startup]


def _python_class() -> str | None:
    """En un exe congelado no hay módulo importable: el dispatcher va en main()."""
    return None if getattr(sys, "frozen", False) else f"{__name__}.SentinelService"


def install(home: str | Path, *, startup: str = "auto") -> str:
    """Instala el servicio (requiere administrador)."""
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
    """Desinstala el servicio (requiere administrador)."""
    _, util = _require_service()
    util.RemoveService(SERVICE_NAME)
    clear_service_home()


def start(wait: int = 15) -> None:
    """Arranca el servicio y espera a que esté en ejecución."""
    _, util = _require_service()
    util.StartService(SERVICE_NAME)
    if wait:
        import win32service

        util.WaitForServiceStatus(SERVICE_NAME, win32service.SERVICE_RUNNING, wait)


def stop(wait: int = 15) -> None:
    """Detiene el servicio."""
    _, util = _require_service()
    if wait:
        util.StopServiceWithDeps(SERVICE_NAME, waitSecs=wait)
    else:
        util.StopService(SERVICE_NAME)


def status() -> str:
    """Devuelve el estado actual del servicio."""
    win32service, util = _require_service()
    try:
        info = util.QueryServiceStatus(SERVICE_NAME)
    except Exception as exc:  # pywintypes.error no siempre importable en tests
        raise ServiceUnavailable(f"No se pudo consultar {SERVICE_NAME}: {exc}") from exc
    states = {
        win32service.SERVICE_STOPPED: "detenido",
        win32service.SERVICE_START_PENDING: "iniciando",
        win32service.SERVICE_STOP_PENDING: "deteniendo",
        win32service.SERVICE_RUNNING: "en ejecución",
        win32service.SERVICE_CONTINUE_PENDING: "continuando",
        win32service.SERVICE_PAUSE_PENDING: "pausando",
        win32service.SERVICE_PAUSED: "pausado",
    }
    return states.get(info[1], f"desconocido ({info[1]})")


def dispatch_frozen() -> bool:
    """Registra el dispatcher del SCM cuando el exe congelado se inicia sin args."""
    if not getattr(sys, "frozen", False) or len(sys.argv) > 1:
        return False
    if not service_available():
        return False
    import servicemanager

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(SentinelService)
    servicemanager.StartServiceCtrlDispatcher()
    return True


# La clase solo existe cuando pywin32 está disponible.
SentinelService: Any = None
if service_available():  # pragma: no cover - depende del entorno
    import servicemanager
    import win32service
    from win32serviceutil import ServiceFramework

    class SentinelService(ServiceFramework):  # type: ignore[no-redef]
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, args: list[str]) -> None:
            super().__init__(args)
            # pywin32 >= 312 no crea StopEvent en ServiceFramework.
            self.StopEvent = threading.Event()
            self.monitor: Any = None

        def SvcDoRun(self) -> None:
            try:
                self.monitor = build_monitor(load_service_home())
                self.monitor.start()
                while not self.StopEvent.wait(1.0):
                    if not getattr(self.monitor, "is_alive", True):
                        break
            except Exception as exc:  # el SCM debe recibir el error, no un traceback mudo
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
