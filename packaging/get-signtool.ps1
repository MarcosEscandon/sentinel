<#
.SYNOPSIS
    Descarga un signtool.exe portable desde el paquete NuGet oficial de
    Microsoft Windows SDK Build Tools. No requiere administrador ni instalar
    el SDK completo.

.DESCRIPTION
    Guarda el binario en packaging\tools\signtool.exe. build.ps1 lo detecta
    automáticamente. Esta herramienta solo firma: para producción necesitas
    además un certificado EV/OV de firma de código.

.EXAMPLE
    .\packaging\get-signtool.ps1
    .\packaging\build.ps1 -Sign
#>
[CmdletBinding()]
param(
    [string]$Version = '10.0.26100.7627'
)

$ErrorActionPreference = 'Stop'

$paquete = "microsoft.windows.sdk.buildtools.$Version"
$url = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/$Version/$paquete.nupkg"
$destino = Join-Path $PSScriptRoot 'tools'
$zipTemporal = Join-Path $env:TEMP "$paquete.zip"
$extraido = Join-Path $env:TEMP "sentinel-sdk-$Version"

Write-Host "Descargando $paquete desde NuGet..."
Invoke-WebRequest -Uri $url -OutFile $zipTemporal -UseBasicParsing

Remove-Item -LiteralPath $extraido -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $zipTemporal -DestinationPath $extraido -Force

$origen = Get-ChildItem -LiteralPath $extraido -Recurse -Filter 'signtool.exe' |
    Where-Object FullName -like '*\x64\signtool.exe' |
    Select-Object -First 1
if (-not $origen) {
    throw 'No se encontró signtool.exe x64 dentro del paquete NuGet.'
}

New-Item -ItemType Directory -Force -Path $destino | Out-Null
Copy-Item -LiteralPath $origen.FullName -Destination (Join-Path $destino 'signtool.exe') -Force
Write-Host "signtool.exe listo en: $(Join-Path $destino 'signtool.exe')"
Write-Host 'Recuerda definir SENTINEL_CERT_THUMBPRINT o SENTINEL_CERT_SUBJECT antes de firmar.'
