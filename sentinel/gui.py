"""Minimal Sentinel GUI built with tkinter (stdlib).

The window provides a non-blocking scanner, a results log, and basic
quarantine management. The core logic lives in public methods
(``scan_path``, ``format_summary``, ``refresh_quarantine``) that can be used
without opening a window via ``SentinelGUI(headless=True)``.
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

from . import __version__, trust
from .config import ScanConfig
from .core.database import ScanDatabase
from .core.logging import AuditLogger
from .core.models import ScanResult
from .core.quarantine import Quarantine, QuarantineEntry, QuarantineIntegrityError
from .engine.scanner import Scanner, summarize

if TYPE_CHECKING:  # Annotations do not require Tk in headless mode.
    from tkinter import ttk

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_SIGNATURES = DATA_DIR / "signatures.json"
DEFAULT_HOME = Path(os.environ.get("SENTINEL_HOME", str(Path.home() / ".sentinel")))
POLL_INTERVAL_MS = 100


def _human_size(size: int) -> str:
    """Format bytes with human-readable units for the summary."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


class SentinelGUI:
    """Main Sentinel window.

    Parameters
    ----------
    home:
        Data directory (history, quarantine, and audit log). Defaults to
        ``$SENTINEL_HOME`` or ``~/.sentinel``, just like the CLI.
    signatures:
        Path to ``signatures.json``; defaults to the bundled copy.
    root:
        An existing Tk window (optional, useful for tests).
    headless:
        If ``True``, no window is created: only the logic is initialized.
    config:
        Scanner configuration; defaults to ``ScanConfig()``.
    public_key:
        Optional trusted Ed25519 public key for the signature database.
    require_signature:
        Verify the database signature before scanning (on by default).
    """

    def __init__(
        self,
        home: str | Path | None = None,
        signatures: str | Path | None = None,
        *,
        root: Any | None = None,
        headless: bool = False,
        config: ScanConfig | None = None,
        public_key: str | Path | None = None,
        require_signature: bool = True,
    ) -> None:
        self.home = Path(home) if home is not None else DEFAULT_HOME
        self.signatures_path = (
            Path(signatures) if signatures is not None else DEFAULT_SIGNATURES
        )
        self.config = config or ScanConfig()
        self.public_key = Path(public_key) if public_key is not None else None
        self.require_signature = require_signature
        self.database = ScanDatabase(self.home / "history.db")
        self.quarantine = Quarantine(self.home / "quarantine")
        self.logger = AuditLogger(self.home / "audit.jsonl")

        self.queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._scanning = False
        self._last_result: ScanResult | None = None
        self._last_scan_id: int | None = None
        self.status = "Ready"
        self.logs: list[str] = []

        # Widget references remain None in headless mode.
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
        """Create the widgets of the main window."""
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
        ttk.Label(controls, text="Path:").pack(side="left")
        ttk.Entry(controls, textvariable=self.path_var).pack(
            side="left", fill="x", expand=True, padx=6
        )
        ttk.Button(controls, text="Browse", command=self.browse_path).pack(side="left")
        ttk.Button(controls, text="Scan", command=self.start_scan).pack(
            side="left", padx=(6, 0)
        )

        # ttk has no Text widget: use tk.Text inside a ttk frame.
        log_frame = ttk.LabelFrame(main, text="Scan log", padding=6)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=14, wrap="word", state="disabled")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        q_frame = ttk.LabelFrame(main, text="Quarantine", padding=6)
        q_frame.pack(fill="both", expand=True, pady=(8, 0))
        columns = ("id", "name", "source", "motivo", "fecha")
        self.tree = ttk.Treeview(q_frame, columns=columns, show="headings", height=8)
        headings = {
            "id": ("ID", 150),
            "name": ("Name", 160),
            "source": ("Origin", 260),
            "motivo": ("Reason", 130),
            "fecha": ("Date", 160),
        }
        for key, (label, width) in headings.items():
            self.tree.heading(key, text=label)
            self.tree.column(key, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True)

        actions = ttk.Frame(q_frame)
        actions.pack(fill="x", pady=(6, 0))
        ttk.Button(actions, text="Refresh", command=self.refresh_quarantine).pack(
            side="left"
        )
        ttk.Button(actions, text="Restore", command=self.restore_selected).pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(actions, text="Delete", command=self.delete_selected).pack(
            side="left", padx=(6, 0)
        )

        ttk.Label(main, textvariable=self.status_var, anchor="w").pack(fill="x", pady=(8, 0))
        self._append_log(f"Sentinel {__version__} ready. Signatures: {self.signatures_path}")
        self.refresh_quarantine()

    def run(self) -> None:
        """Start the Tk event loop (does nothing in headless mode)."""
        if self.root is not None:
            self.root.mainloop()

    def shutdown(self) -> None:
        """Close the window if this instance created it."""
        if self.root is not None and self._owns_root:
            self.root.destroy()
            self.root = None

    def browse_path(self) -> None:
        """Select a directory using the native dialog."""
        if self._dialogs is None:
            return
        chosen = self._dialogs.askdirectory(title="Select the path to scan")
        if chosen and self.path_var is not None:
            self.path_var.set(chosen)

    def start_scan(self) -> None:
        """Start a background scan without blocking the interface."""
        path = self._current_path()
        if not path:
            self._append_log("Enter a valid path before scanning.")
            return
        if self._scanning:
            self._append_log("A scan is already in progress.")
            return
        self._scanning = True
        self._set_status(f"Scanning {path} ...")
        self._append_log(f"Starting scan: {path}")
        self._thread = threading.Thread(
            target=self._scan_worker, args=(path,), name="sentinel-scan", daemon=True
        )
        self._thread.start()
        if self.root is not None:
            self.root.after(POLL_INTERVAL_MS, self._poll_queue)

    def scan_path(self, path: str) -> ScanResult:
        """Scan ``path`` synchronously and update the status and log."""
        scanner = self._build_scanner()
        self._set_status(f"Scanning {path} ...")
        self.logger.scan_start(
            [path],
            signatures_version=scanner.signatures.version,
            revision=scanner.signatures.revision,
        )
        try:
            result = scanner.scan(path)
        except (OSError, ValueError, TypeError) as exc:
            self._report_error(f"Error scanning {path}: {exc}")
            self._set_status("Scan failed")
            raise
        self._finish_scan(result, prompt_quarantine=False)
        return result

    def format_summary(self, result: ScanResult) -> str:
        """Return a human-readable summary with counts, severity, and findings."""
        severity = result.max_severity
        level = severity.value.upper() if severity else "NONE"
        lines = [
            "SCAN REPORT",
            f"  Started    : {result.started_at}",
            f"  Duration   : {result.duration_seconds:.2f} s",
            f"  Files      : {result.files_scanned}  ({_human_size(result.bytes_scanned)})",
            f"  Skipped    : {result.skipped}",
            f"  Allowed    : {result.allowed}",
            f"  Container  : {result.container_entries} entries",
            f"  Errors     : {len(result.errors)}",
            f"  Findings   : {len(result.findings)}  (max severity: {level})",
        ]
        for finding in result.sorted_findings():
            lines.append(
                f"  [{finding.severity.value.upper()}] {finding.rule_id} "
                f"({finding.detection.value})"
            )
            lines.append(f"      {finding.path}")
            lines.append(f"      {finding.description}")
        if not result.findings:
            lines.append("  No threats found.")
        return "\n".join(lines)

    def refresh_quarantine(self) -> list[QuarantineEntry]:
        """Refresh the ``Treeview`` and return the quarantine entries."""
        try:
            entries = self.quarantine.list()
        except (OSError, ValueError) as exc:
            self._report_error(f"Could not read the quarantine: {exc}")
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
        """Restore the selected entry to its original path."""
        entry_id = self._selected_id()
        if not entry_id:
            return
        try:
            path = self.quarantine.restore(entry_id)
            self.logger.emit("quarantine.restore", id=entry_id, path=str(path))
            self._append_log(f"Restored: {path}")
        except (KeyError, ValueError, OSError, QuarantineIntegrityError) as exc:
            self._report_error(f"Could not restore {entry_id}: {exc}")
        self.refresh_quarantine()

    def delete_selected(self) -> None:
        """Permanently delete the selected entry after confirmation."""
        entry_id = self._selected_id()
        if not entry_id:
            return
        if not self._confirm(f"Permanently delete entry {entry_id}?"):
            return
        try:
            self.quarantine.delete(entry_id)
            self.logger.emit("quarantine.delete", id=entry_id)
            self._append_log(f"Deleted entry: {entry_id}")
        except (KeyError, ValueError, OSError) as exc:
            self._report_error(f"Could not delete {entry_id}: {exc}")
        self.refresh_quarantine()

    def quarantine_findings(
        self,
        result: ScanResult,
        *,
        confirmed: bool | None = None,
        scan_id: int | None = None,
    ) -> list[str]:
        """Quarantine detected files; return the created IDs."""
        targets: dict[str, Any] = {}
        for finding in result.findings:
            targets.setdefault(finding.path, finding)
        if not targets:
            return []
        if confirmed is None:
            confirmed = self._confirm(
                f"Quarantine {len(targets)} detected file(s)?"
            )
        if not confirmed:
            self._append_log("Quarantine canceled; no files were moved.")
            return []

        moved: list[str] = []
        paths: list[str] = []
        for path, finding in targets.items():
            if not Path(path).is_file():
                continue
            try:
                entry_id = self.quarantine.add(path, finding.rule_id, finding.sha256)
            except (OSError, FileNotFoundError, ValueError) as exc:
                self._report_error(f"Could not quarantine {path}: {exc}")
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
                self._report_error(f"Could not update the history: {exc}")
        if moved:
            self._append_log(f"Quarantined: {len(moved)} file(s).")
        return moved

    def _build_scanner(self) -> Scanner:
        """Load verified signatures and build a ``Scanner`` with the configured settings."""
        signatures = trust.load_database(
            self.signatures_path,
            home=self.home,
            public_key=self.public_key,
            require_signature=self.require_signature,
        )
        # YARA is optional; the GUI relies on signatures, content, and heuristics.
        return Scanner(signatures, self.config, yara=None)

    def _scan_worker(self, path: str) -> None:
        """Scan thread body: publish events to the queue."""
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
        """Process the queue on the main Tk thread every 100 ms."""
        while True:
            try:
                message = self.queue.get_nowait()
            except queue.Empty:
                break
            self._handle_message(message)
        if self._scanning and self.root is not None:
            self.root.after(POLL_INTERVAL_MS, self._poll_queue)

    def _handle_message(self, message: dict[str, Any]) -> None:
        """Handle an event coming from the scan thread."""
        kind = message.get("type")
        if kind == "progress":
            event = str(message.get("event", ""))
            count = int(message.get("count", 0))
            if event == "finding":
                self._set_status(f"Finding detected: {message.get('path', '')}")
            elif event == "file" and count % 25 == 0:
                self._set_status(f"Files scanned: {count}")
        elif kind == "result":
            self._finish_scan(message["result"], prompt_quarantine=True)
        elif kind == "error":
            self._scanning = False
            self._report_error(str(message.get("message", "Unknown error")))
            self._set_status("Scan failed")

    def _finish_scan(self, result: ScanResult, *, prompt_quarantine: bool) -> None:
        """Save the report, display the summary, and refresh the quarantine."""
        self._scanning = False
        self._last_result = result
        self._append_log(self.format_summary(result))
        severity = result.max_severity
        level = severity.value.upper() if severity else "NONE"
        self._set_status(
            f"Completed: {len(result.findings)} finding(s) · max severity: {level}"
        )
        try:
            self._last_scan_id = self.database.save_scan(result)
            for finding in result.findings:
                self.logger.finding(finding)
            self.logger.scan_finish({"scan_id": self._last_scan_id, **summarize(result)})
        except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
            self._report_error(f"Could not save the history: {exc}")
        if prompt_quarantine and result.findings:
            self.quarantine_findings(result, scan_id=self._last_scan_id)
        self.refresh_quarantine()

    def _current_path(self) -> str:
        """Return the path entered in the text field."""
        return self.path_var.get().strip() if self.path_var is not None else ""

    def _selected_id(self) -> str:
        """Return the ID selected in the quarantine list."""
        if self.tree is None:
            return ""
        selection = self.tree.selection()
        return str(selection[0]) if selection else ""

    def _confirm(self, message: str) -> bool:
        """Ask for confirmation with ``messagebox``; cancel if there is no window."""
        if self._messagebox is None:
            return False
        try:
            return bool(self._messagebox.askyesno("Sentinel", message))
        except Exception as exc:  # noqa: BLE001 - Tcl may fail while closing the window
            self._report_error(f"Could not display the confirmation: {exc}")
            return False

    def _set_status(self, text: str) -> None:
        """Update the status label (and its headless copy)."""
        self.status = text
        if self.status_var is not None:
            self.status_var.set(text)

    def _append_log(self, message: str) -> None:
        """Append a line to the read-only log."""
        self.logs.append(message)
        if self.log_text is None:
            return
        self.log_text.configure(state="normal")
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _report_error(self, message: str) -> None:
        """Report an error in the log and duplicate it on stderr."""
        self._append_log(f"! {message}")
        print(f"[Sentinel] {message}", file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    """Optional entry point for opening the GUI without going through the CLI."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-gui", description="Sentinel graphical interface."
    )
    parser.add_argument("--home", default=str(DEFAULT_HOME), help="Data directory.")
    parser.add_argument(
        "--signatures", default=str(DEFAULT_SIGNATURES), help="Path to signatures.json."
    )
    args = parser.parse_args(argv)
    app = SentinelGUI(args.home, args.signatures)
    app.run()
    return 0


__all__ = ["DEFAULT_HOME", "DEFAULT_SIGNATURES", "SentinelGUI", "main"]
