# -*- mode: python ; coding: utf-8 -*-
"""Especificación de PyInstaller >= 6 para Sentinel (Windows 10/11 x64).

No se ejecuta directamente: usar ``packaging\\build.ps1``. Si se invoca a mano:

    pyinstaller --noconfirm --clean packaging/sentinel.spec

Variables de entorno admitidas (las fija build.ps1):

* ``SENTINEL_ONEFILE=1`` -> un único ejecutable (por defecto).
  ``SENTINEL_ONEFILE=0`` -> modo directorio (dist\\sentinel\\sentinel.exe).
* ``SENTINEL_CONSOLE=0`` -> sin consola (por defecto).
  ``SENTINEL_CONSOLE=1`` -> consola visible, útil para depurar.

Opción documentada para compilar siempre con consola: cambiar el valor por
defecto de ``CONSOLE`` más abajo, o ejecutar ``.\\packaging\\build.ps1 -Console``.
El nombre ``name="sentinel"`` produce ``dist\\sentinel.exe`` en Windows.
"""

import glob
import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# SPECPATH lo define PyInstaller; el fallback permite inspeccionar el spec con
# herramientas que no inyectan ese globals (por ejemplo, py_compile).
_spec_dir = Path(globals().get("SPECPATH") or globals().get("__file__", ".")).resolve()
if _spec_dir.is_file():
    _spec_dir = _spec_dir.parent

PROJECT_ROOT = _spec_dir.parent  # packaging/ está dentro de la raíz del proyecto
BUILD_DIR = PROJECT_ROOT / "build"
DATA_DIR = PROJECT_ROOT / "sentinel" / "data"

# --- Archivos auxiliares generados en build/ (texto, no se versionan) --------
# El entry point declarado es sentinel.cli:main. No podemos usar __main__.py
# como script raíz porque contiene imports relativos; este launcher replica
# exactamente el comportamiento del console_script del paquete.
BUILD_DIR.mkdir(parents=True, exist_ok=True)

launcher = BUILD_DIR / "sentinel_launcher.py"
launcher.write_text(
    '"""Launcher generado por packaging/sentinel.spec; no editar."""\n'
    "from sentinel.cli import main\n\n"
    "raise SystemExit(main())\n",
    encoding="utf-8",
)

# En modo sin consola, PyInstaller deja sys.stdout/sys.stderr a None en Windows.
# argparse --version escribe en stdout; sin este hook el smoke test del build
# terminaría con un AttributeError. Con consola visible el hook es inofensivo.
runtime_hook = BUILD_DIR / "sentinel_windowed_stdio.py"
runtime_hook.write_text(
    '"""Hook generado por packaging/sentinel.spec; no editar."""\n'
    "import os\n"
    "import sys\n\n"
    "if sys.platform == 'win32':\n"
    "    _salida = open(os.devnull, 'w', encoding='utf-8')\n"
    "    _entrada = open(os.devnull, 'r', encoding='utf-8')\n"
    "    if sys.stdout is None:\n"
    "        sys.stdout = _salida\n"
    "    if sys.stderr is None:\n"
    "        sys.stderr = _salida\n"
    "    if sys.stdin is None:\n"
    "        sys.stdin = _entrada\n",
    encoding="utf-8",
)

# --- Modo de empaquetado ----------------------------------------------------
ONEFILE = os.environ.get("SENTINEL_ONEFILE", "1") == "1"
CONSOLE = os.environ.get("SENTINEL_CONSOLE", "0") == "1"

# --- Datos del paquete ------------------------------------------------------
# Se copian con la misma estructura que usa sentinel.cli:
#   DATA_DIR = Path(__file__).parent / "data"
datas = []
for patron, destino in (
    (str(DATA_DIR / "*.json"), "sentinel/data"),
    (str(DATA_DIR / "*.sig"), "sentinel/data"),
    (str(DATA_DIR / "*.pub"), "sentinel/data"),
    (str(DATA_DIR / "yara" / "*.yar"), "sentinel/data/yara"),
    (str(DATA_DIR / "iocs" / "*.csv"), "sentinel/data/iocs"),
    (str(DATA_DIR / "iocs" / "*.com"), "sentinel/data/iocs"),
):
    for origen in sorted(glob.glob(patron)):
        datas.append((origen, destino))

if not any(Path(origen).name == "signatures.json" for origen, _ in datas):
    raise RuntimeError("Falta sentinel/data/signatures.json; revisa la instalación del proyecto.")

# build.ps1 genera estos archivos antes de invocar PyInstaller. Se empaquetan
# dentro de sentinel/data para poder verificarlos con `sentinel integrity verify`.
for nombre in ("manifest.json", "manifest.json.sig"):
    candidato = BUILD_DIR / nombre
    if candidato.is_file():
        datas.append((str(candidato), "sentinel/data"))

# --- Imports opcionales -----------------------------------------------------
# Si la dependencia no está instalada, PyInstaller avisa pero no falla.
hiddenimports = [
    "cryptography",
    "cryptography.exceptions",
    "cryptography.hazmat.primitives",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "regex",
    "yara",
    "win32service",
    "servicemanager",  # pywin32 expone 'servicemanager' (no 'win32servicemanager')
    "win32serviceutil",
    "watchdog",
    "tkinter",
]
for paquete in ("cryptography", "yara", "watchdog"):
    try:
        hiddenimports.extend(collect_submodules(paquete))
    except Exception:  # dependencia opcional ausente en el entorno de compilación
        pass
hiddenimports = list(dict.fromkeys(hiddenimports))

# --- Exclusiones ------------------------------------------------------------
# NO excluir urllib/http/ssl/email (usa update_signatures) ni sqlite3, lzma,
# zipfile o tarfile (historial, contenedores y cuarentena).
excludes = [
    "pytest",
    "_pytest",
    "ruff",
    "IPython",
    "jupyter",
    "notebook",
    "matplotlib",
    "numpy",
    "pandas",
    "scipy",
    "sklearn",
    "PIL",
    "cv2",
    "PyQt5",
    "PyQt6",
    "PySide2",
    "PySide6",
    "wx",
    "pip",
    "setuptools",
    "pkg_resources",
    "unittest",
    "doctest",
    "pydoc",
    "pydoc_data",
    "multiprocessing",
    "asyncio",
    "curses",
    "turtle",
    "lib2to3",
    "test",
    "tests",
]

# Icono opcional: si añades packaging/sentinel.ico se usará automáticamente.
icon_path = _spec_dir / "sentinel.ico"
icon = str(icon_path) if icon_path.is_file() else None

analysis = Analysis(
    [str(launcher)],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(runtime_hook)],
    excludes=excludes,
    noarchive=False,
)

pyz = PYZ(analysis.pure)

opciones_comunes = dict(
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    console=CONSOLE,
    disable_windowed_traceback=not CONSOLE,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
)

if ONEFILE:
    exe = EXE(
        pyz,
        analysis.scripts,
        analysis.binaries,
        analysis.datas,
        [],
        runtime_tmpdir=None,
        **opciones_comunes,
    )
else:
    exe = EXE(
        pyz,
        analysis.scripts,
        [],
        exclude_binaries=True,
        **opciones_comunes,
    )
    coll = COLLECT(
        exe,
        analysis.binaries,
        analysis.datas,
        strip=False,
        upx=True,
        upx_exclude=[],
        name="sentinel",
    )
