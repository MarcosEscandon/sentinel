<#
.SYNOPSIS
    Builds Sentinel with PyInstaller (Windows 10/11 x64) and signs it if requested.

.DESCRIPTION
    Cleans build/ and dist/, runs packaging/sentinel.spec, verifies the
    resulting executable and runs a smoke test with --version. The certificate
    is selected from the Windows store via environment variables:
    no passwords or .pfx files are passed in this script.

.EXAMPLE
    .\packaging\build.ps1

.EXAMPLE
    .\packaging\build.ps1 -Configuration Debug -Console -OneFile:$false

.EXAMPLE
    $env:SENTINEL_CERT_SUBJECT = "Sentinel Scanner Ltd."
    .\packaging\build.ps1 -Sign
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # By default, dist\sentinel.exe is generated (a single file).
    # Use -OneFile:$false to generate dist\sentinel\sentinel.exe.
    [switch]$OneFile = $true,

    # Visible console: useful for debugging; by default, builds without a console.
    [switch]$Console,

    # Authenticode signing with an EV/OV certificate from the Windows store.
    [switch]$Sign
)

# Continue prevents informational stderr from PyInstaller/signtool from turning
# into a terminating ErrorRecord in Windows PowerShell 5.1 when the caller
# redirects 2>&1. Real failures are checked with $LASTEXITCODE and explicit throw.
$ErrorActionPreference = 'Continue'

# In PS 7.x, we also disable native stderr treatment as an error.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$python = if ($env:SENTINEL_PYTHON) { $env:SENTINEL_PYTHON } else { 'python' }
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$specPath = Join-Path $PSScriptRoot 'sentinel.spec'
$buildDir = Join-Path $ProjectRoot 'build'
$distDir = Join-Path $ProjectRoot 'dist'

if (-not (Test-Path -LiteralPath $specPath -PathType Leaf)) {
    throw "PyInstaller specification not found: $specPath"
}

Push-Location -LiteralPath $ProjectRoot
try {
    # --- Interpreter ---------------------------------------------------------
    & $python --version
    if ($LASTEXITCODE -ne 0) {
        throw "Could not run Python ('$python'). Adjust SENTINEL_PYTHON if needed."
    }

    & $python -c "import struct; raise SystemExit(0 if struct.calcsize('P') == 8 else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw 'A 64-bit (x64) Python installation is required.'
    }

    # --- PyInstaller: use it if already installed, install it if missing ------
    $pyinstallerVersion = & $python -m PyInstaller --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'PyInstaller is not installed; installing pyinstaller>=6 ...'
        & $python -m pip install 'pyinstaller>=6'
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not install PyInstaller >= 6.'
        }
        $pyinstallerVersion = & $python -m PyInstaller --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw 'PyInstaller >= 6 does not work after installation.'
        }
    }
    Write-Host "PyInstaller detected: $pyinstallerVersion"

    # --- Cleanup -----------------------------------------------------------
    foreach ($directory in @($buildDir, $distDir)) {
        if (Test-Path -LiteralPath $directory) {
            Write-Host "Cleaning $directory"
            Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction Stop
        }
    }

    # --- Integrity manifest for the packaged data ----------------------------
    # Generated before PyInstaller so that the spec includes it in the exe.
    $manifestPath = Join-Path $buildDir 'manifest.json'
    $manifestCode = @"
import sys
sys.path.insert(0, r'$ProjectRoot')
from sentinel.integrity import build_manifest
build_manifest(r'$ProjectRoot\sentinel\data', r'$manifestPath')
"@
    & $python -c $manifestCode
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not generate the integrity manifest.'
    }
    Write-Host "Manifest generated: $manifestPath"

    if ($env:SENTINEL_PRIVATE_KEY) {
        $signCode = @"
import sys
from pathlib import Path
sys.path.insert(0, r'$ProjectRoot')
from sentinel import crypto
path = Path(r'$manifestPath')
Path(str(path) + '.sig').write_bytes(
    crypto.sign_payload(path.read_bytes(), r'$env:SENTINEL_PRIVATE_KEY')
)
"@
        & $python -c $signCode
        if ($LASTEXITCODE -ne 0) {
            throw 'Could not sign the integrity manifest.'
        }
        Write-Host 'Manifest signed with Ed25519.'
    }

    # The spec reads these variables to decide onefile mode and console visibility.
    $env:SENTINEL_ONEFILE = if ($OneFile) { '1' } else { '0' }
    $env:SENTINEL_CONSOLE = if ($Console) { '1' } else { '0' }

    # --- Build --------------------------------------------------------
    $pyinstallerArgs = @(
        '--noconfirm',
        '--clean',
        '--distpath', $distDir,
        '--workpath', $buildDir,
        $specPath
    )
    if ($Configuration -eq 'Debug') {
        $pyinstallerArgs = @('--log-level', 'DEBUG', '--debug') + $pyinstallerArgs
    }
    else {
        $pyinstallerArgs = @('--log-level', 'INFO') + $pyinstallerArgs
    }

    & $python -m PyInstaller @pyinstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller exited with exit code $LASTEXITCODE."
    }

    # --- exe verification ------------------------------------------------
    $exePath = if ($OneFile) {
        Join-Path $distDir 'sentinel.exe'
    }
    else {
        Join-Path (Join-Path $distDir 'sentinel') 'sentinel.exe'
    }
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "Expected executable was not generated: $exePath"
    }
    Write-Host "Executable generated: $exePath"

    # --- Authenticode signing (optional) --------------------------------------
    if ($Sign) {
        $signtoolPath = $null

        # 1) Explicit path (useful with the portable signtool from packaging/get-signtool.ps1).
        if ($env:SENTINEL_SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:SENTINEL_SIGNTOOL_PATH -PathType Leaf)) {
            $signtoolPath = $env:SENTINEL_SIGNTOOL_PATH
        }

        # 2) Local copy downloaded by get-signtool.ps1.
        if (-not $signtoolPath) {
            $localSigntool = Join-Path $PSScriptRoot 'tools\signtool.exe'
            if (Test-Path -LiteralPath $localSigntool -PathType Leaf) {
                $signtoolPath = $localSigntool
            }
        }

        # 3) PATH.
        if (-not $signtoolPath) {
            $signtoolCommand = Get-Command -Name 'signtool' -ErrorAction SilentlyContinue
            if ($signtoolCommand) {
                $signtoolPath = $signtoolCommand.Source
            }
        }

        if (-not $signtoolPath) {
            # Windows SDK: search for the latest available version of the x64 binary.
            $patterns = @()
            $programFilesX86 = ${env:ProgramFiles(x86)}
            $programFiles = $env:ProgramFiles
            if ($programFilesX86) {
                $patterns += Join-Path $programFilesX86 'Windows Kits\10\bin\*\x64\signtool.exe'
            }
            if ($programFiles) {
                $patterns += Join-Path $programFiles 'Windows Kits\10\bin\*\x64\signtool.exe'
            }
            foreach ($pattern in $patterns) {
                $found = Get-ChildItem -Path $pattern -File -ErrorAction SilentlyContinue |
                    Sort-Object -Property FullName -Descending |
                    Select-Object -First 1
                if ($found) {
                    $signtoolPath = $found.FullName
                    break
                }
            }
        }
        if (-not $signtoolPath) {
            throw 'signtool.exe not found. Install the Windows SDK (Windows 10/11 SDK).'
        }

        $subject = $env:SENTINEL_CERT_SUBJECT
        $thumbprint = $env:SENTINEL_CERT_THUMBPRINT
        if (-not $subject -and -not $thumbprint) {
            throw 'For -Sign, set SENTINEL_CERT_SUBJECT or SENTINEL_CERT_THUMBPRINT with a certificate installed in the Windows store.'
        }

        $timestampUrl = if ($env:SENTINEL_TIMESTAMP_URL) {
            $env:SENTINEL_TIMESTAMP_URL
        }
        else {
            'http://timestamp.digicert.com'
        }

        $signArgs = @('sign', '/fd', 'SHA256', '/tr', $timestampUrl, '/td', 'SHA256')
        if ($thumbprint) {
            $signArgs += @('/sha1', $thumbprint)
        }
        else {
            $signArgs += @('/n', $subject)
        }
        $signArgs += $exePath

        & $signtoolPath @signArgs
        if ($LASTEXITCODE -ne 0) {
            throw "signtool exited with exit code $LASTEXITCODE."
        }
        Write-Host 'Authenticode signature applied and timestamped.'
    }

    # --- Smoke test ---------------------------------------------------------
    Write-Host "Smoke test: `"$exePath`" --version"
    & $exePath --version
    if ($LASTEXITCODE -ne 0) {
        throw "The smoke test (--version) exited with code $LASTEXITCODE."
    }
    if (-not $Console) {
        Write-Host 'Note: without a console, --version output goes to NUL; the smoke test validates the exit code.'
    }

    Write-Host 'Build completed successfully.'
}
finally {
    Pop-Location
}
