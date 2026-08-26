<#
.SYNOPSIS
    Upgrade the bd (beads) CLI to a pinned release.

.DESCRIPTION
    bd ships as a standalone binary with no self-update, so upgrading means download, verify,
    replace. This script does that with a checksum gate and keeps the outgoing binary next to the
    new one, so a rollback is a rename rather than another download.

    AGENTS SHOULD NOT RUN THIS. It writes outside the repo, into the user's %LOCALAPPDATA%,
    the same way tools/install-gui.ps1 writes into %APPDATA%.

    Defaults target v1.2.2. Note that v1.2.2 is v1.1.2's code under a higher version number:
    v1.2.0 and v1.2.1 were published by accident without release testing, and v1.2.2 re-releases
    the tested 1.1 line, so the 1.2.x-only features are deliberately not in it.

    Upgrading migrates the local Dolt schema forward, and that is one-way. Run `bd dolt push`
    first so the remote has a copy.

.PARAMETER Version
    Release version to install, without the leading "v". Default 1.2.2.

.PARAMETER Sha256
    Expected SHA256 of the release zip. Must be supplied when -Version is overridden; the default
    only matches 1.2.2 windows_amd64. Get it from the release's checksums.txt.

.PARAMETER WhatIf
    Resolve and report what would happen, download nothing.

.EXAMPLE
    .\tools\upgrade-bd.ps1
    .\tools\upgrade-bd.ps1 -Version 1.3.0 -Sha256 <hash-from-checksums.txt>
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string] $Version = '1.2.2',
    [string] $Sha256  = '1f00c29cd9599e182a4a4e829f5210daca2da14155920aee2836d8bc613b2feb'
)

$ErrorActionPreference = 'Stop'

if ($Version -ne '1.2.2' -and
    $Sha256 -eq '1f00c29cd9599e182a4a4e829f5210daca2da14155920aee2836d8bc613b2feb') {
    throw "-Version $Version was given without a matching -Sha256. The default hash is for 1.2.2 only; " +
          "take the correct one from https://github.com/gastownhall/beads/releases/download/v$Version/checksums.txt"
}

$asset  = "beads_${Version}_windows_amd64.zip"
$url    = "https://github.com/gastownhall/beads/releases/download/v$Version/$asset"
$instDir = Join-Path $env:LOCALAPPDATA 'Programs\bd'
$target  = Join-Path $instDir 'bd.exe'
$zip     = Join-Path $env:TEMP $asset
$unpack  = Join-Path $env:TEMP "beads_${Version}_unpack"

$current = if (Test-Path $target) { (& $target version) -join ' ' } else { '(not installed)' }
Write-Host "Current : $current"
Write-Host "Target  : v$Version"
Write-Host "Source  : $url"
Write-Host "Install : $target"

if (-not $PSCmdlet.ShouldProcess($target, "install bd v$Version")) { return }

# A running bd (the SessionStart/PreCompact hooks shell out to it) holds the file open.
$busy = Get-Process -Name 'bd' -ErrorAction SilentlyContinue
if ($busy) { throw "bd is running (PID $($busy.Id -join ', ')). Close it and retry." }

Write-Host "`nDownloading..."
Invoke-WebRequest -Uri $url -OutFile $zip

$got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($got -ne $Sha256.ToLower()) {
    throw "SHA256 mismatch, refusing to install.`n  expected $Sha256`n  got      $got"
}
Write-Host "SHA256 OK: $got"

if (Test-Path $unpack) { Remove-Item $unpack -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $unpack -Force

$new = Get-ChildItem $unpack -Recurse -Filter 'bd.exe' | Select-Object -First 1
if (-not $new) { throw "bd.exe not found under $unpack" }

if (Test-Path $target) {
    $backup = Join-Path $instDir 'bd-previous.exe'
    if (Test-Path $backup) { Remove-Item $backup -Force }
    Move-Item $target $backup
    Write-Host "Previous binary kept at $backup (rollback = rename it back)"
}

New-Item -ItemType Directory -Force -Path $instDir | Out-Null
Copy-Item $new.FullName $target -Force
Remove-Item $unpack -Recurse -Force
Remove-Item $zip -Force

Write-Host "`nInstalled: $((& $target version) -join ' ')"
Write-Host "Next: confirm the new flag exists -- bd prime --no-memories | Measure-Object -Character"
