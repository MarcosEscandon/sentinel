<#
.SYNOPSIS
    Downloads a portable signtool.exe from the official Microsoft Windows SDK
    Build Tools NuGet package. Requires neither administrator privileges nor
    installation of the full SDK.

.DESCRIPTION
    Saves the binary to packaging\tools\signtool.exe. build.ps1 detects it
    automatically. This tool only signs: for production you also need an EV/OV
    code-signing certificate.

.EXAMPLE
    .\packaging\get-signtool.ps1
    .\packaging\build.ps1 -Sign
#>
[CmdletBinding()]
param(
    [string]$Version = '10.0.26100.7627'
)

$ErrorActionPreference = 'Stop'

$package = "microsoft.windows.sdk.buildtools.$Version"
$url = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/$Version/$package.nupkg"
$destination = Join-Path $PSScriptRoot 'tools'
$zipTemp = Join-Path $env:TEMP "$package.zip"
$extracted = Join-Path $env:TEMP "sentinel-sdk-$Version"

Write-Host "Downloading $package from NuGet..."
Invoke-WebRequest -Uri $url -OutFile $zipTemp -UseBasicParsing

Remove-Item -LiteralPath $extracted -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -LiteralPath $zipTemp -DestinationPath $extracted -Force

$source = Get-ChildItem -LiteralPath $extracted -Recurse -Filter 'signtool.exe' |
    Where-Object FullName -like '*\x64\signtool.exe' |
    Select-Object -First 1
if (-not $source) {
    throw 'x64 signtool.exe not found inside the NuGet package.'
}

New-Item -ItemType Directory -Force -Path $destination | Out-Null
Copy-Item -LiteralPath $source.FullName -Destination (Join-Path $destination 'signtool.exe') -Force
Write-Host "signtool.exe ready at: $(Join-Path $destination 'signtool.exe')"
Write-Host 'Remember to set SENTINEL_CERT_THUMBPRINT or SENTINEL_CERT_SUBJECT before signing.'
