<#
.SYNOPSIS
    Downloads a portable, hash-verified signtool.exe from the official Microsoft
    Windows SDK Build Tools NuGet package. Requires neither administrator
    privileges nor installation of the full SDK.

.DESCRIPTION
    Saves the binary to packaging\tools\signtool.exe. build.ps1 detects it
    automatically. This tool only signs: for production you also need an EV/OV
    code-signing certificate stored on a token/HSM.

    Two SHA-256 pins are checked before the tool is installed:
      1. the downloaded .nupkg (supply-chain anchor), and
      2. the extracted x64\signtool.exe (exact binary).
    Both pins are fail-closed: a mismatch aborts the download. If you change
    -Version you MUST also supply -PackageSha256 and -ToolSha256, or explicitly
    opt out with -SkipHashCheck for local experiments only.

.EXAMPLE
    .\packaging\get-signtool.ps1
    .\packaging\build.ps1 -Sign

.EXAMPLE
    .\packaging\get-signtool.ps1 -Version 10.0.26100.7627 -PackageSha256 <sha256> -ToolSha256 <sha256>
#>
[CmdletBinding()]
param(
    [string]$Version = '10.0.26100.7627',
    [string]$PackageSha256 = '34480A26E87C9A127B36997E1AB3C7D93812384DCE484877E11816D3A6B1CCCE',
    [string]$ToolSha256 = '2083C6A58A817AEDF558D88A251D3E90D3041855041C13134C280CE3E7440D2E',
    [switch]$SkipHashCheck
)

$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') {
    throw 'Version must be a four-part numeric NuGet version (e.g. 10.0.26100.7627).'
}
$expectedPackage = $PackageSha256 -replace '[^a-fA-F0-9]', ''
$expectedTool = $ToolSha256 -replace '[^a-fA-F0-9]', ''
if (-not $SkipHashCheck) {
    if ($expectedPackage -notmatch '^[a-fA-F0-9]{64}$' -or $expectedTool -notmatch '^[a-fA-F0-9]{64}$') {
        throw 'PackageSha256 and ToolSha256 must be 64 hex characters. Supply the pins for this Version.'
    }
    if ($Version -ne '10.0.26100.7627') {
        throw 'No pinned hashes for this Version. Supply -PackageSha256 and -ToolSha256, or -SkipHashCheck for local experiments only.'
    }
} else {
    Write-Warning 'Hash verification is DISABLED. Use this only for local experiments, never for release builds.'
}

if (([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) -eq 0) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}

$package = "microsoft.windows.sdk.buildtools.$Version"
$url = "https://api.nuget.org/v3-flatcontainer/microsoft.windows.sdk.buildtools/$Version/$package.nupkg"
$destination = Join-Path $PSScriptRoot 'tools'
$zipTemp = Join-Path $env:TEMP "$package-$([guid]::NewGuid().ToString('N')).zip"
$extracted = Join-Path $env:TEMP "sentinel-sdk-$Version-$([guid]::NewGuid().ToString('N'))"

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

try {
    Write-Host "Downloading $package from NuGet..."
    Invoke-WebRequest -Uri $url -OutFile $zipTemp -UseBasicParsing

    if (-not $SkipHashCheck) {
        $actualPackage = Get-Sha256 $zipTemp
        if ($actualPackage -ne $expectedPackage) {
            throw "Package SHA-256 mismatch: expected $expectedPackage, got $actualPackage. Aborting."
        }
        Write-Host 'Package SHA-256 verified.'
    }

    Expand-Archive -LiteralPath $zipTemp -DestinationPath $extracted -Force

    $source = Get-ChildItem -LiteralPath $extracted -Recurse -Filter 'signtool.exe' |
        Where-Object FullName -like '*\x64\signtool.exe' |
        Select-Object -First 1
    if (-not $source) {
        throw 'x64 signtool.exe not found inside the NuGet package.'
    }

    if (-not $SkipHashCheck) {
        $actualTool = Get-Sha256 $source.FullName
        if ($actualTool -ne $expectedTool) {
            throw "signtool.exe SHA-256 mismatch: expected $expectedTool, got $actualTool. Aborting."
        }
        Write-Host 'signtool.exe SHA-256 verified.'
    }

    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    $target = Join-Path $destination 'signtool.exe'
    Copy-Item -LiteralPath $source.FullName -Destination $target -Force

    # Best-effort: keep the signing tool private to the current user.
    if ($env:USERNAME) {
        & icacls $target /inheritance:r /grant:r "$($env:USERNAME):(F)" 2>$null | Out-Null
    }

    Write-Host "signtool.exe ready at: $target"
    Write-Host 'Remember to set SENTINEL_CERT_THUMBPRINT or SENTINEL_CERT_SUBJECT before signing.'
}
finally {
    Remove-Item -LiteralPath $zipTemp -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $extracted -Recurse -Force -ErrorAction SilentlyContinue
}
