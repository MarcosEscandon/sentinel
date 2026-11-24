<#
.SYNOPSIS
    Compila Sentinel con PyInstaller (Windows 10/11 x64) y lo firma si se pide.

.DESCRIPTION
    Limpia build/ y dist/, ejecuta packaging/sentinel.spec, verifica el
    ejecutable resultante y lanza un smoke test con --version. El certificado
    se selecciona desde el almacén de Windows mediante variables de entorno:
    no se pasan contraseñas ni archivos .pfx en este script.

.EXAMPLE
    .\packaging\build.ps1

.EXAMPLE
    .\packaging\build.ps1 -Configuration Debug -Console -OneFile:$false

.EXAMPLE
    $env:SENTINEL_CERT_SUBJECT = "Sentinel Scanner S.L."
    .\packaging\build.ps1 -Sign
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    # Por defecto se genera dist\sentinel.exe (un único archivo).
    # Usa -OneFile:$false para generar dist\sentinel\sentinel.exe.
    [switch]$OneFile = $true,

    # Consola visible: útil para depurar; por defecto se compila sin consola.
    [switch]$Console,

    # Firma Authenticode con un certificado EV/OV del almacén de Windows.
    [switch]$Sign
)

# Continue evita que el stderr informativo de PyInstaller/signtool se convierta
# en ErrorRecord terminante en Windows PowerShell 5.1 si el llamador redirige
# 2>&1. Los fallos reales se comprueban con $LASTEXITCODE y throw explícito.
$ErrorActionPreference = 'Continue'

# En PS 7.x, además, desactivamos el tratamiento de stderr como error nativo.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$python = if ($env:SENTINEL_PYTHON) { $env:SENTINEL_PYTHON } else { 'python' }
$ProjectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
$specPath = Join-Path $PSScriptRoot 'sentinel.spec'
$buildDir = Join-Path $ProjectRoot 'build'
$distDir = Join-Path $ProjectRoot 'dist'

if (-not (Test-Path -LiteralPath $specPath -PathType Leaf)) {
    throw "No se encontró la especificación de PyInstaller: $specPath"
}

Push-Location -LiteralPath $ProjectRoot
try {
    # --- Intérprete ---------------------------------------------------------
    & $python --version
    if ($LASTEXITCODE -ne 0) {
        throw "No se pudo ejecutar Python ('$python'). Ajusta SENTINEL_PYTHON si hace falta."
    }

    & $python -c "import struct; raise SystemExit(0 if struct.calcsize('P') == 8 else 1)"
    if ($LASTEXITCODE -ne 0) {
        throw 'Se requiere una instalación de Python de 64 bits (x64).'
    }

    # --- PyInstaller: usarlo si ya está, instalarlo si falta -----------------
    $pyinstallerVersion = & $python -m PyInstaller --version 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'PyInstaller no está instalado; instalando pyinstaller>=6 ...'
        & $python -m pip install 'pyinstaller>=6'
        if ($LASTEXITCODE -ne 0) {
            throw 'No se pudo instalar PyInstaller >= 6.'
        }
        $pyinstallerVersion = & $python -m PyInstaller --version 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw 'PyInstaller >= 6 no funciona después de la instalación.'
        }
    }
    Write-Host "PyInstaller detectado: $pyinstallerVersion"

    # --- Limpieza -----------------------------------------------------------
    foreach ($directorio in @($buildDir, $distDir)) {
        if (Test-Path -LiteralPath $directorio) {
            Write-Host "Limpiando $directorio"
            Remove-Item -LiteralPath $directorio -Recurse -Force -ErrorAction Stop
        }
    }

    # --- Manifiesto de integridad de los datos empaquetados -----------------
    # Se genera antes de PyInstaller para que el spec lo incluya en el exe.
    $manifestPath = Join-Path $buildDir 'manifest.json'
    $manifestCode = @"
import sys
sys.path.insert(0, r'$ProjectRoot')
from sentinel.integrity import build_manifest
build_manifest(r'$ProjectRoot\sentinel\data', r'$manifestPath')
"@
    & $python -c $manifestCode
    if ($LASTEXITCODE -ne 0) {
        throw 'No se pudo generar el manifiesto de integridad.'
    }
    Write-Host "Manifiesto generado: $manifestPath"

    if ($env:SENTINEL_PRIVATE_KEY) {
        $signCode = @"
import sys
from pathlib import Path
sys.path.insert(0, r'$ProjectRoot')
from sentinel import crypto
ruta = Path(r'$manifestPath')
Path(str(ruta) + '.sig').write_bytes(
    crypto.sign_payload(ruta.read_bytes(), r'$env:SENTINEL_PRIVATE_KEY')
)
"@
        & $python -c $signCode
        if ($LASTEXITCODE -ne 0) {
            throw 'No se pudo firmar el manifiesto de integridad.'
        }
        Write-Host 'Manifiesto firmado con Ed25519.'
    }

    # El spec lee estas variables para decidir onefile y visibilidad de consola.
    $env:SENTINEL_ONEFILE = if ($OneFile) { '1' } else { '0' }
    $env:SENTINEL_CONSOLE = if ($Console) { '1' } else { '0' }

    # --- Compilación --------------------------------------------------------
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
        throw "PyInstaller terminó con código de salida $LASTEXITCODE."
    }

    # --- Verificación del exe ------------------------------------------------
    $exePath = if ($OneFile) {
        Join-Path $distDir 'sentinel.exe'
    }
    else {
        Join-Path (Join-Path $distDir 'sentinel') 'sentinel.exe'
    }
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "No se generó el ejecutable esperado: $exePath"
    }
    Write-Host "Ejecutable generado: $exePath"

    # --- Firma Authenticode (opcional) --------------------------------------
    if ($Sign) {
        $signtoolPath = $null

        # 1) Ruta explícita (útil con el signtool portable de packaging/get-signtool.ps1).
        if ($env:SENTINEL_SIGNTOOL_PATH -and (Test-Path -LiteralPath $env:SENTINEL_SIGNTOOL_PATH -PathType Leaf)) {
            $signtoolPath = $env:SENTINEL_SIGNTOOL_PATH
        }

        # 2) Copia local descargada por get-signtool.ps1.
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
            # Windows SDK: buscar la última versión disponible del bin x64.
            $patrones = @()
            $programFilesX86 = ${env:ProgramFiles(x86)}
            $programFiles = $env:ProgramFiles
            if ($programFilesX86) {
                $patrones += Join-Path $programFilesX86 'Windows Kits\10\bin\*\x64\signtool.exe'
            }
            if ($programFiles) {
                $patrones += Join-Path $programFiles 'Windows Kits\10\bin\*\x64\signtool.exe'
            }
            foreach ($patron in $patrones) {
                $encontrado = Get-ChildItem -Path $patron -File -ErrorAction SilentlyContinue |
                    Sort-Object -Property FullName -Descending |
                    Select-Object -First 1
                if ($encontrado) {
                    $signtoolPath = $encontrado.FullName
                    break
                }
            }
        }
        if (-not $signtoolPath) {
            throw 'No se encontró signtool.exe. Instala el Windows SDK (Windows 10/11 SDK).'
        }

        $subject = $env:SENTINEL_CERT_SUBJECT
        $thumbprint = $env:SENTINEL_CERT_THUMBPRINT
        if (-not $subject -and -not $thumbprint) {
            throw 'Para -Sign define SENTINEL_CERT_SUBJECT o SENTINEL_CERT_THUMBPRINT con un certificado instalado en el almacén de Windows.'
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
            throw "signtool terminó con código de salida $LASTEXITCODE."
        }
        Write-Host 'Firma Authenticode aplicada y sellada en el tiempo.'
    }

    # --- Smoke test ---------------------------------------------------------
    Write-Host "Smoke test: `"$exePath`" --version"
    & $exePath --version
    if ($LASTEXITCODE -ne 0) {
        throw "El smoke test (--version) terminó con código de salida $LASTEXITCODE."
    }
    if (-not $Console) {
        Write-Host 'Nota: sin consola, la salida de --version va a NUL; el smoke test valida el código de salida.'
    }

    Write-Host 'Compilación completada correctamente.'
}
finally {
    Pop-Location
}
