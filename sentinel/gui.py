"""Interfaz gráfica mínima de Sentinel construida con tkinter (stdlib).

La ventana ofrece un escáner que no bloquea la interfaz, un registro de
resultados y la gestión básica de la cuarentena. La lógica importante vive en
métodos públicos (``scan_path``, ``format_summary``, ``refresh_quarantine``)
que pueden usarse sin abrir ventana mediante ``SentinelGUI(headless=True)``.
"""

from __future__ import annotations

import os
import queue
import sqlite3
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import __version__
from .config import ScanConfig
from .core.database import ScanDatabase
from .core.logging import AuditLogger
from .core.models import ScanResult
from .core.quarantine import Quarantine, QuarantineEntry, QuarantineIntegrityError
from .engine.scanner import Scanner, summarize
from .engine.signatures import SignatureDatabase

if TYPE_CHECKING:  # Las anotaciones no requieren Tk en modo headless.
    from tkinter import ttk

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_SIGNATURES = DATA_DIR / "signatures.json"
DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))
POLL_INTERVAL_MS = 100


def _human_size(size: int) -> str:
    """Formatea bytes con unidades legibles para el resumen."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


class SentinelGUI:
    """Ventana principal de Sentinel.

    Parámetros
    ----------
    home:
        Directorio de datos (historial, cuarentena y auditoría). Por defecto
        usa ``$SENTINEL_HOME`` o ``~/.sentinel``, igual que la CLI.
    signatures:
        Ruta a ``signatures.json``; por defecto la incluida en el paquete.
    root:
        Ventana Tk ya creada (opcional, útil para pruebas).
    headless:
        Si es ``True`` no se crea ninguna ventana: solo se inicializa la lógica.
    config:
        Configuración del escáner; por defecto ``ScanConfig()``.
    """

    def __init__(
        self,
        home: str | Path | None = None,
        signatures: str | Path | None = None,
        *,
        root: Any | None = None,
        headless: bool = False,
        config: ScanConfig | None = None,
    ) -> None:
        self.home = Path(home) if home is not None else DEFAULT_HOME
        self.signatures_path = (
            Path(signatures) if signatures is not None else DEFAULT_SIGNATURES
        )
        self.config = config or ScanConfig()
        self.database = ScanDatabase(self.home / "history.db")
        self.quarantine = Quarantine(self.home / "quarantine")
        self.logger = AuditLogger(self.home / "audit.jsonl")

        self.queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._scanning = False
        self._last_result: ScanResult | None = None
        self._last_scan_id: int | None = None
        self.status = "Listo"
        self.logs: list[str] = []

        # Referencias a widgets: se quedan en None en modo headless.
        self.root = root
        self.path_var: Any | None = None
        self.status_var: Any | None = None
        self.log_text: Any | None = None
        self.tree: ttk.Treeview | None = None
        self._tk: Any | None = None
        self._ttk: Any | None = None
        self._dialogs: Any | None = None
        self._messagebox: Any | None = None
        self._owns_root = False

        if not headless:
            self._build_window()

    def _build_window(self) -> None:
        """Crea los widgets de la ventana principal."""
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk

        self._tk = tk
        self._ttk = ttk
        self._dialogs = filedialog
        self._messagebox = messagebox
        self._owns_root = self.root is None
        if self.root is None:
            self.root = tk.Tk()
        self.root.title(f"Sentinel {__version__}")
        self.root.geometry("860x620")
        self.root.minsize(640, 480)

        self.path_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value=self.status)

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=(0, 8))
        ttk.Label(controls, text="Ruta:").pack(side="left")
        ttk.Entry(controls, textvariable=self.path_var).pack(
            side="left", fill="x", expand=True, padx=6
        )
        ttk.Button(controls, text="Examinar", command=self.browse_path).pack(side="left")
        ttk.Button(controls, text="Escanear", command=self.start_scan).pack(
            side="left", padx=(6, 0)
        )

        # ttk no incluye un widget Text: se usa tk.Text dentro de un marco ttk.
        log_frame = ttk.LabelFrame(main, text="Registro de escaneo", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=14, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        q_frame = ttk.LabelFrame(main, text="Cuarentena", padding=6)
        q_frame.pack(fill="both", expand=True, pady=(8, 0))
        columns = ("id", "nombre", "origen", "motivo", "fecha")
        self.tree = ttk.Treeview(q_frame, columns=columns, show="headings", height=8)
        headings = {
            "id": ("ID", 150),
            "nombre": ("Nombre", 160),
            "origen": ("Origen", 260),
            "motivo": ("Motivo", 130),
            "fecha": ("Fecha", 160),
        }
        for key, (label, width) in headings.items():
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

        actions = ttk.Frame(q_frame)
        actions.pack(fill="x", pady=(6, 0))
        ttk.Button(actions, text="Actualizar", command=self.refresh_quarantine).pack(
            side="left"
        )
        ttk.Button(actions, text="Restaurar", command=self.restore_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Eliminar", command=self.delete_selected).pack(
            side="left", padx=(6, 0)
        )

        ttk.Label(main, textvariable=self.status_var, anchor="w").pack(fill="x", pady=(8, 0))
        self._append_log(f"Sentinel {__version__} listo. Firmas: {self.signatures_path}")
        self.refresh_quarantine()

    def run(self) -> None:
        """Inicia el bucle de eventos de Tk (no hace nada en modo headless)."""
        if self.root is not None:
            self.root.mainloop()

    def shutdown(self) -> None:
        """Cierra la ventana si esta instancia fue quien la creó."""
        if self.root is not None and self._owns_root:
            self.root.destroy()
            self.root = None

    def browse_path(self) -> None:
        """Selecciona un directorio mediante el diálogo nativo."""
        if self._dialogs is None:
            return
        chosen = self._dialogs.askdirectory(title="Selecciona la ruta a escanear")
        if chosen and self.path_var is not None:
            self.path_var.set(chosen)

    def start_scan(self) -> None:
        """Lanza un escaneo en segundo plano sin bloquear la interfaz."""
        path = self._current_path()
        if not path:
            self._append_log("Indica una ruta válida antes de escanear.")
            return
        if self._scanning:
            self._append_log("Ya hay un escaneo en curso.")
            return
        self._scanning = True
        self._set_status(f"Escaneando {path} ...")
        self._append_log(f"Iniciando escaneo: {path}")
        self._thread = threading.Thread(
            target=self._scan_worker, args=(path,), name="sentinel-scan", daemon=True
        )
        self._thread.start()
        if self.root is not None:
            self.root.after(POLL_INTERVAL_MS, self._poll_queue)

    def scan_path(self, path: str) -> ScanResult:
        """Escanea ``path`` de forma síncrona y actualiza estado y registro."""
        scanner = self._build_scanner()
        self._set_status(f"Escaneando {path} ...")
        self.logger.scan_start(
            [path],
            signatures_version=scanner.signatures.version,
            revision=scanner.signatures.revision,
        )
        try:
            result = scanner.scan(path)
        except (OSError, ValueError, TypeError) as exc:
            self._report_error(f"Error al escanear {path}: {exc}")
            self._set_status("Error en el escaneo")
            raise
        self._finish_scan(result, prompt_quarantine=False)
        return result

    def format_summary(self, result: ScanResult) -> str:
        """Devuelve un resumen legible con recuentos, severidad y hallazgos."""
        severity = result.max_severity
        level = severity.value.upper() if severity else "NINGUNA"
        lines = [
            "INFORME DE ESCANEO",
            f"  Inicio     : {result.started_at}",
            f"  Duración   : {result.duration_seconds:.2f} s",
            f"  Archivos   : {result.files_scanned}  ({_human_size(result.bytes_scanned)})",
            f"  Omitidos   : {result.skipped}",
            f"  Excluidos  : {result.allowed}",
            f"  Contenedor : {result.container_entries} entradas",
            f"  Errores    : {len(result.errors)}",
            f"  Hallazgos  : {len(result.findings)}  (severidad máxima: {level})",
        ]
        for finding in result.sorted_findings():
            lines.append(
                f"  [{finding.severity.value.upper()}] {finding.rule_id} "
                f"({finding.detection.value})"
            )
            lines.append(f"      {finding.path}")
            lines.append(f"      {finding.description}")
        if not result.findings:
            lines.append("  No se encontraron amenazas.")
        return "\n".join(lines)

    def refresh_quarantine(self) -> list[QuarantineEntry]:
        """Actualiza el ``Treeview`` y devuelve las entradas de cuarentena."""
        try:
            entries = self.quarantine.list()
        except (OSError, ValueError) as exc:
            self._report_error(f"No se pudo leer la cuarentena: {exc}")
            return []
        if self.tree is not None:
            self.tree.delete(*self.tree.get_children())
            for entry in entries:
                self.tree.insert(
                    "",
                    "end",
                    iid=entry.id,
                    values=(
                        entry.id,
                        entry.original_name,
                        entry.original_path,
                        entry.reason,
                        entry.quarantined_at,
                    ),
                )
        return entries

    def restore_selected(self) -> None:
        """Restaura a su ruta original la entrada seleccionada."""
        entry_id = self._selected_id()
        if not entry_id:
            return
        try:
            path = self.quarantine.restore(entry_id)
            self.logger.emit("quarantine.restore", id=entry_id, path=str(path))
            self._append_log(f"Restaurado: {path}")
        except (KeyError, ValueError, OSError, QuarantineIntegrityError) as exc:
            self._report_error(f"No se pudo restaurar {entry_id}: {exc}")
        self.refresh_quarantine()

    def delete_selected(self) -> None:
        """Elimina definitivamente la entrada seleccionada tras confirmarlo."""
        entry_id = self._selected_id()
        if not entry_id:
            return
        if not self._confirm(f"¿Eliminar definitivamente la entrada {entry_id}?"):
            return
        try:
            self.quarantine.delete(entry_id)
            self.logger.emit("quarantine.delete", id=entry_id)
            self._append_log(f"Eliminada entrada: {entry_id}")
        except (KeyError, ValueError, OSError) as exc:
            self._report_error(f"No se pudo eliminar {entry_id}: {exc}")
        self.refresh_quarantine()

    def quarantine_findings(
        self,
        result: ScanResult,
        *,
        confirmed: bool | None = None,
        scan_id: int | None = None,
    ) -> list[str]:
        """Mueve a cuarentena los archivos detectados; devuelve los IDs creados."""
        targets: dict[str, Any] = {}
        for finding in result.findings:
            targets.setdefault(finding.path, finding)
        if not targets:
            return []
        if confirmed is None:
            confirmed = self._confirm(
                f"¿Enviar {len(targets)} archivo(s) detectado(s) a cuarentena?"
            )
        if not confirmed:
            self._append_log("Cuarentena cancelada; no se movieron archivos.")
            return []

        moved: list[str] = []
        paths: list[str] = []
        for path, finding in targets.items():
            if not Path(path).is_file():
                continue
            try:
                entry_id = self.quarantine.add(path, finding.rule_id, finding.sha256)
            except (OSError, FileNotFoundError, ValueError) as exc:
                self._report_error(f"No se pudo poner en cuarentena {path}: {exc}")
                result.errors.append({"path": path, "error": str(exc)})
                continue
            self.logger.emit("quarantine.add", id=entry_id, path=path, reason=finding.rule_id)
            moved.append(entry_id)
            paths.append(path)
            for item in result.findings:
                if item.path == path:
                    item.quarantined = True
                    item.quarantine_id = entry_id
        if paths and scan_id is not None:
            try:
                self.database.mark_quarantined(paths, scan_id)
            except (OSError, sqlite3.Error) as exc:
                self._report_error(f"No se pudo actualizar el historial: {exc}")
        if moved:
            self._append_log(f"En cuarentena: {len(moved)} archivo(s).")
        return moved

    def _build_scanner(self) -> Scanner:
        """Carga las firmas y construye un ``Scanner`` con la configuración dada."""
        signatures = SignatureDatabase.load(self.signatures_path)
        # YARA es opcional; la GUI se apoya en firmas, contenido y heurística.
        return Scanner(signatures, self.config, yara=None)

    def _scan_worker(self, path: str) -> None:
        """Cuerpo del hilo de escaneo: publica eventos en la cola."""
        try:
            scanner = self._build_scanner()
            self.logger.scan_start(
                [path],
                signatures_version=scanner.signatures.version,
                revision=scanner.signatures.revision,
            )

            def progress(event: str, item: str, count: int) -> None:
                self.queue.put(
                    {"type": "progress", "event": event, "path": item, "count": count}
                )

            result = scanner.scan(path, progress)
            self.queue.put({"type": "result", "result": result})
        except (OSError, ValueError, TypeError) as exc:
            self.queue.put({"type": "error", "message": str(exc)})

    def _poll_queue(self) -> None:
        """Procesa la cola en el hilo principal de Tk cada 100 ms."""
        while True:
            try:
                message = self.queue.get_nowait()
            except queue.Empty:
                break
            self._handle_message(message)
        if self._scanning and self.root is not None:
            self.root.after(POLL_INTERVAL_MS, self._poll_queue)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Interpreta un evento procedente del hilo de escaneo."""
        kind = message.get("type")
        if kind == "progress":
            event = str(message.get("event", ""))
            count = int(message.get("count", 0))
            if event == "finding":
                self._set_status(f"Hallazgo detectado: {message.get('path', '')}")
            elif event == "file" and count % 25 == 0:
                self._set_status(f"Archivos analizados: {count}")
        elif kind == "result":
            self._finish_scan(message["result"], prompt_quarantine=True)
        elif kind == "error":
            self._scanning = False
            self._report_error(str(message.get("message", "Error desconocido")))
            self._set_status("Error en el escaneo")

    def _finish_scan(self, result: ScanResult, *, prompt_quarantine: bool) -> None:
        """Guarda el informe, muestra el resumen y actualiza la cuarentena."""
        self._scanning = False
        self._last_result = result
        self._append_log(self.format_summary(result))
        severity = result.max_severity
        level = severity.value.upper() if severity else "NINGUNA"
        self._set_status(
            f"Completado: {len(result.findings)} hallazgo(s) · severidad máxima: {level}"
        )
        try:
            self._last_scan_id = self.database.save_scan(result)
            for finding in result.findings:
                self.logger.finding(finding)
            self.logger.scan_finish({"scan_id": self._last_scan_id, **summarize(result)})
        except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
            self._report_error(f"No se pudo guardar el historial: {exc}")
        if prompt_quarantine and result.findings:
            self.quarantine_findings(result, scan_id=self._last_scan_id)
        self.refresh_quarantine()

    def _current_path(self) -> str:
        """Devuelve la ruta escrita en el campo de texto."""
        return self.path_var.get().strip() if self.path_var is not None else ""

    def _selected_id(self) -> str:
        """Devuelve el identificador seleccionado en la lista de cuarentena."""
        if self.tree is None:
            return ""
        selection = self.tree.selection()
        return str(selection[0]) if selection else ""

    def _confirm(self, message: str) -> bool:
        """Pide confirmación con ``messagebox``; sin ventana se cancela."""
        if self._messagebox is None:
            return False
        try:
            return bool(self._messagebox.askyesno("Sentinel", message))
        except Exception as exc:  # noqa: BLE001 - Tcl puede fallar al cerrar la ventana
            self._report_error(f"No se pudo mostrar la confirmación: {exc}")
            return False

    def _set_status(self, text: str) -> None:
        """Actualiza la etiqueta de estado (y su copia en modo headless)."""
        self.status = text
        if self.status_var is not None:
            self.status_var.set(text)

    def _append_log(self, message: str) -> None:
        """Añade una línea al registro de solo lectura."""
        self.logs.append(message)
        if self.log_text is None:
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _report_error(self, message: str) -> None:
        """Muestra un error en el registro y lo duplica en stderr."""
        self._append_log(f"! {message}")
        print(f"[Sentinel] {message}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada opcional para abrir la GUI sin pasar por la CLI."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-gui", description="Interfaz gráfica de Sentinel."
    )
    parser.add_argument("--home", default=str(DEFAULT_HOME), help="Directorio de datos.")
    parser.add_argument(
        "--signatures", default=str(DEFAULT_SIGNATURES), help="Ruta a signatures.json."
    )
    args = parser.parse_args(argv)
    app = SentinelGUI(args.home, args.signatures)
    app.run()
    return 0


__all__ = ["DEFAULT_HOME", "DEFAULT_SIGNATURES", "SentinelGUI", "main"]
