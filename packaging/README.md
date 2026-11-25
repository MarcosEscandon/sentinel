# Packaging Sentinel (Windows 10/11 x64)

This directory contains the recipe for building Sentinel as a Windows
executable. It does not modify the source code: the spec generates a launcher
and a *runtime hook* (both text files) in `build/` that replicate the
`sentinel.cli:main` entry point and fix standard output in windowed mode.

Files:

* `sentinel.spec` — PyInstaller >= 6 specification.
* `build.ps1` — build, verification and optional signing script.
* `get-signtool.ps1` — downloads a portable `signtool.exe` from NuGet.

## Requirements

* 64-bit Windows 10 or 11.
* 64-bit Python 3.10 or newer (the same environment where the project was
  installed).
* PyInstaller >= 6. `build.ps1` installs it with `pip` if it is not available.
* Only for `-Sign`: `signtool.exe` (from the Windows SDK or downloaded with
  `.\packaging\get-signtool.ps1`) and an **EV or OV** code-signing certificate
  installed in the Windows `CurrentUser\My` store (on a token/HSM for EV).
  `get-signtool.ps1` does not need administrator privileges: it extracts the
  binary from the official NuGet package to `packaging\tools\signtool.exe`.

## 1. Install dependencies

From the project root (`C:\Users\marco\Mine\sentinel`):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev,signing,hardening,service,realtime]"
```

`dev` and `hardening` cover tests and `regex` with a timeout; `signing` adds the
preferred Ed25519 backend, while verification also works with the standard
library. `service` and `realtime` add Windows service management and `watchdog`;
the monitor also works without them using polling or the native
`ReadDirectoryChangesW` backend on Windows.

## 2. Build

```powershell
.\packaging\build.ps1
```

or, explicitly:

```powershell
.\packaging\build.ps1 -Configuration Release -OneFile
```

If PowerShell blocks local scripts:

```powershell
powershell -ExecutionPolicy Bypass -File .\packaging\build.ps1
```

The default result is `dist\sentinel.exe` (a single file). The script cleans
`build/` and `dist/`, generates `build/manifest.json` with the SHA-256 hashes of
`sentinel/data`, runs PyInstaller with `packaging/sentinel.spec`, checks that the
exe exists and runs `dist\sentinel.exe --version` as a smoke test. Any failure
terminates with `throw` and a nonzero exit code.

The manifest (and its signature if `SENTINEL_PRIVATE_KEY` is configured) is
packaged inside `sentinel/data`. In `-OneFile:$false` mode it can be verified
with:

```powershell
sentinel integrity verify _internal\sentinel\data `
  --manifest _internal\sentinel\data\manifest.json `
  --public-key _internal\sentinel\data\signatures.json.pub
```

| Parameter | Effect |
| --- | --- |
| `-Configuration Release` (default) | Normal build (`--log-level INFO`). |
| `-Configuration Debug` | Adds `--debug` and `--log-level DEBUG`. |
| `-OneFile` (default) | Produces `dist\sentinel.exe`. |
| `-OneFile:$false` | Directory mode: `dist\sentinel\sentinel.exe`. |
| `-Console` | Builds **with** a visible console (by default, without one). |
| `-Sign` | Signs the exe with Authenticode (see section 3). |

Supported environment variables (set by the script):

* `SENTINEL_PYTHON`: path to the interpreter if `python` is not on the `PATH`.
* `SENTINEL_ONEFILE`: `1` (default) or `0` in the spec.
* `SENTINEL_CONSOLE`: `0` (default) or `1` in the spec.
* `SENTINEL_TIMESTAMP_URL`: timestamp server for signing.
* `SENTINEL_SIGNTOOL_PATH`: explicit path to `signtool.exe`.
* `SENTINEL_CERT_THUMBPRINT` / `SENTINEL_CERT_SUBJECT`: certificate selectors.
* `SENTINEL_PRIVATE_KEY`: Ed25519 private key for signing the data manifest.

You can also build with a console by editing the default value of `CONSOLE` in
`sentinel.spec`, or by running directly:

```powershell
$env:SENTINEL_CONSOLE = '1'
pyinstaller --noconfirm --clean packaging/sentinel.spec
```

In windowed mode (the default), PyInstaller leaves `sys.stdout` and `sys.stderr`
as `None` on Windows. The generated runtime hook redirects them to `NUL`, so the
smoke test validates the **exit code** (0) but does not display the `--version`
output. Use `-Console` if you want to see that output.

## 3. Signing with an EV/OV certificate

Install the certificate in the Windows personal store (for EV, the token must be
connected; the PIN will be requested interactively). Do not store the password
or the `.pfx` in the repository: the script only selects the certificate by
subject or thumbprint.

```powershell
# Option A: by subject name
$env:SENTINEL_CERT_SUBJECT = "My Organization Ltd."

# Option B: by SHA-1 thumbprint (takes precedence if both are defined)
$env:SENTINEL_CERT_THUMBPRINT = "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"

# Optional: timestamp server
$env:SENTINEL_TIMESTAMP_URL = "http://timestamp.digicert.com"

.\packaging\build.ps1 -Sign
```

The script invokes:

```text
signtool sign /fd SHA256 /tr <timestamp> /td SHA256 (/n <subject> | /sha1 <thumbprint>) dist\sentinel.exe
```

The timestamp is important: it keeps the signature valid after the certificate
expires. To check the result:

```powershell
signtool verify /pa /v dist\sentinel.exe
```

Note that a freshly signed executable may show SmartScreen warnings until it
accumulates reputation; that is independent of the signature being valid.

With a **self-signed test certificate** the signature is applied and timestamped,
but `signtool verify /pa` fails with "root not trusted" while the CA is not
trusted: this is expected. In this environment the full chain was validated by
temporarily adding the certificate to the `CurrentUser` `Root` store with
`certutil -user -addstore -f Root test.cer`;
`signtool verify /pa /v dist\sentinel.exe` returned `Successfully verified`
(1 file, 0 errors). The certificate was removed immediately afterwards with
`certutil -user -delstore Root <thumbprint>` and confirmed no longer in the
store. For production use an EV/OV certificate from a public CA: **do not trust
a test certificate on a real machine**. The full procedure for issuance,
signing and AppLocker/WDAC rules is in `docs/EV_OV_HANDOFF.md`.

## 4. Optional symbols (PDB)

PyInstaller does not create a new PDB: it can only pull in the `.pdb` files that
already exist in your Python installation and dependencies. If you need symbols
for debugging:

```powershell
.\packaging\build.ps1 -Configuration Debug -OneFile:$false -Console
```

In directory mode (`-OneFile:$false`) it is easier to keep the available PDBs
next to `dist\sentinel\sentinel.exe`. In `onefile` they remain inside the bundle
and are not delivered separately. **Do not distribute the PDBs with the final
product**: keep them on your symbol server or in internal storage.

## 5. The exe signature does NOT replace Ed25519 verification

Authenticode signing and Ed25519 verification of IOC signatures are two
distinct, complementary controls:

* **Authenticode** demonstrates that `sentinel.exe` was not modified and comes
  from your organization (Windows trust chain).
* **Ed25519** demonstrates that `signatures.json` was issued by the holder of
  the private key and is not an old version (revision control).

An attacker could replace the signature database even if the exe is correctly
signed. Every runtime entry point therefore fails closed when the database is
unsigned or was modified. In production, always update with the trusted public
key:

```powershell
sentinel signatures update --url https://example.local/signatures.json --public-key public.pem
```

The Ed25519 private key **never** goes into the package or the exe. Signing the
binary does not enable or replace this step.

## 6. Troubleshooting

* `sentinel/data/signatures.json not found`: the spec requires this file;
  check that the project is intact at `C:\Users\marco\Mine\sentinel` (the script
  itself can be run from any directory).
* `Hidden import ... not found` warnings: these are expected for optional
  dependencies (`yara`, `watchdog`, `pywin32`, etc.) not installed in the build
  environment. Install the corresponding extra if you want that feature in the
  exe.
* If the smoke test fails in windowed mode, rebuild with `-Console` to see the
  real error.
* To use another interpreter: `$env:SENTINEL_PYTHON = "C:\path\to\.venv\Scripts\python.exe"`.

## Features available in the exe

The executable includes the native monitoring backend (`ReadDirectoryChangesW`
via `ctypes`), so on Windows it does not need `watchdog` or `pywin32` for
`sentinel monitor`. Notifications use a toast if `winotify` is installed in the
build environment; otherwise a native message box is used. To install the
service **from the exe** there is no need to install the `service` extra
(`pywin32`) on the target machine: the spec includes the required modules. That
extra is only needed when running Sentinel from Python or if the build was made
without `pywin32` installed. Administrative elevation is required.

Verification performed in this environment: `.\packaging\build.ps1 -Console -Sign`
generated `dist\sentinel.exe` (onefile, ~14 MB), applied a test Authenticode
signature with a timestamp and the internal `--version` smoke test returned
`sentinel 0.1.0` with exit code 0. The Ed25519 manifest signature was also
validated in onedir mode. The exe includes `pywin32`, so it supports the service
(although installing it requires elevation).

Observed limitation: when running the freshly built exe from a later session,
**Device Guard/Application Control blocked it** because it came from an
untrusted self-signed CA (`cmd` returned 4551). Trusting the certificate in the
user stores was not enough. This is not a flaw in the spec or the signature: for
production use an EV/OV certificate recognized by Windows. The final functional
tests were run with the Python CLI.
