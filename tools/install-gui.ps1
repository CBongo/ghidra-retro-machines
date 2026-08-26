<#
.SYNOPSIS
    Build the extension and install it into the interactive Ghidra GUI's Extensions dir.

.DESCRIPTION
    The user-facing counterpart to tools/banktest/build-and-test.sh. That script deliberately
    installs into a per-worktree ISOLATED settings dir under build/ghidra-home so concurrent
    agents cannot clobber each other and an open GUI cannot lock files out from under a test
    run. Consequently the loop NEVER refreshes the real GUI install, and the GUI silently
    keeps running whatever build was last unzipped there by hand. This script is that hand
    step, automated.

    It is deliberately DESTRUCTIVE: the existing extension directory is deleted and replaced,
    because that is the only reliable way to drop files removed since the last install. There
    is no stamp-based "already current, skipping" shortcut here (unlike build-and-test.sh) --
    you run this when you want a fresh install, so it always installs.

    Ghidra caches its extension list at startup: RESTART Ghidra after running this.

.PARAMETER SkipBuild
    Skip 'gradle buildExtension' and install the newest zip already in dist/. Without this the
    build always runs -- Gradle's own up-to-date checking is the "only if needed" mechanism, and
    it no-ops in a few seconds when nothing changed.

.PARAMETER Force
    Install even if Ghidra appears to be running. Off by default: on Windows a running Ghidra
    holds locks on its own jars, so the delete can half-succeed and leave a broken install that
    is annoying to diagnose.

.PARAMETER GhidraInstall
    Ghidra install dir to build against. Defaults to $env:GRM_GHIDRA_INSTALL, else
    <ghidraInstallRoot>/ghidra_<ver>_PUBLIC -- where ghidraInstallRoot comes from the
    machine-local ~/.gradle/gradle.properties and <ver> from gradle.properties'
    ghidraTargetVersion. Same convention as build.gradle and build-and-test.sh.

.EXAMPLE
    .\tools\install-gui.ps1
.EXAMPLE
    .\tools\install-gui.ps1 -SkipBuild -Force
.EXAMPLE
    .\tools\install-gui.ps1 -SkipBuild -WhatIf    # resolve and report paths, install nothing
.EXAMPLE
    pwsh -File tools/install-gui.ps1        # from git bash or WSL
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [switch] $SkipBuild,
    [switch] $Force,
    [string] $GhidraInstall
)

$ErrorActionPreference = 'Stop'

function Fail($msg) { Write-Error $msg; exit 1 }
function Step($msg) { Write-Host "== $msg ==" -ForegroundColor Cyan }

# --- 1. Repo root and targeted Ghidra version -----------------------------
# gradle.properties' ghidraTargetVersion is the single source of truth (bead grm-9r7);
# everything else derives from it by convention rather than repeating the version.
$repoRoot = Split-Path -Parent $PSScriptRoot
$gradleProps = Join-Path $repoRoot 'gradle.properties'
if (-not (Test-Path $gradleProps)) { Fail "gradle.properties not found at $gradleProps" }

$targetVersion = (Select-String -Path $gradleProps -Pattern '^ghidraTargetVersion=(.*)$').Matches.Groups[1].Value.Trim()
if (-not $targetVersion) { Fail "ghidraTargetVersion not found in $gradleProps" }

if (-not $GhidraInstall) {
    if ($env:GRM_GHIDRA_INSTALL) {
        $GhidraInstall = $env:GRM_GHIDRA_INSTALL
    }
    else {
        # Derive as build.gradle does: <ghidraInstallRoot>/ghidra_<ver>_PUBLIC, where
        # ghidraInstallRoot is machine-local (~/.gradle/gradle.properties) and <ver> comes from
        # the repo. This used to hardcode a D: drive letter, which only ever worked on the
        # author's machine and put that layout in a public repo (grm-sp93). Refuse rather than
        # guess: a wrong install path fails confusingly downstream, an absent one is diagnosable.
        $gradleHome = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { Join-Path $HOME '.gradle' }
        $installRoot = $null
        foreach ($f in @((Join-Path $gradleHome 'gradle.properties'), $gradleProps)) {
            if (-not (Test-Path $f)) { continue }
            $m = Select-String -Path $f -Pattern '^\s*ghidraInstallRoot\s*=\s*(.+)$' | Select-Object -Last 1
            if ($m) { $installRoot = $m.Matches.Groups[1].Value.Trim(); break }
        }
        if (-not $installRoot) {
            Fail ("cannot locate the Ghidra install. Set ghidraInstallRoot=<dir holding " +
                  "ghidra_${targetVersion}_PUBLIC> in $gradleHome\gradle.properties (see README, " +
                  "'Building'), or set GRM_GHIDRA_INSTALL, or pass -GhidraInstall.")
        }
        # String join rather than Join-Path: Join-Path 'D:' 'x' yields the drive-relative 'D:x'.
        $GhidraInstall = $installRoot.TrimEnd('/', '\') + '/' + "ghidra_${targetVersion}_PUBLIC"
    }
}
$appProps = Join-Path $GhidraInstall 'Ghidra/application.properties'
if (-not (Test-Path $appProps)) { Fail "$appProps not found -- bad Ghidra install dir '$GhidraInstall'?" }

# --- 2. Refuse to clobber a running Ghidra --------------------------------
# Match on the command line, not the process name: Ghidra runs as a plain 'java' process, and
# this box may well have unrelated java running (a Gradle daemon, for one).
if (-not $Force) {
    $running = Get-CimInstance Win32_Process -Filter "Name LIKE 'java%'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'ghidra' -and $_.CommandLine -notmatch 'GradleDaemon|analyzeHeadless' }
    if ($running) {
        Write-Host "Ghidra appears to be running:" -ForegroundColor Yellow
        $running | ForEach-Object { Write-Host "  PID $($_.ProcessId)" }
        Fail "Refusing to replace a live install (its jars are locked). Close Ghidra, or re-run with -Force."
    }
}

# --- 3. Build (Gradle decides whether anything actually needs doing) ------
if ($SkipBuild) {
    Step "skipping build (-SkipBuild)"
}
else {
    # build.gradle checks the GHIDRA_INSTALL_DIR env var FIRST and the ambient one on this
    # machine may be stale, so set it explicitly rather than inherit it -- same reasoning as
    # build-and-test.sh. A version mismatch hard-fails the build (grm-9r7 guard).
    $env:GHIDRA_INSTALL_DIR = $GhidraInstall
    # No hardcoded fallback path here any more: it named a specific gradle install on the
    # author's D: drive (grm-sp93), so for anyone else it was a confusing "file not found"
    # standing in for the real problem, which is that gradle is not on PATH.
    $gradleExe = if ($env:GRM_GRADLE) { $env:GRM_GRADLE }
                 elseif (Get-Command gradle -ErrorAction SilentlyContinue) { 'gradle' }
                 else { $null }
    if (-not $gradleExe) {
        Fail 'gradle not found on PATH -- set GRM_GRADLE to your gradle executable, or add gradle to PATH.'
    }
    Step "gradle buildExtension (GHIDRA_INSTALL_DIR=$GhidraInstall)"
    & $gradleExe -p $repoRoot buildExtension
    if ($LASTEXITCODE -ne 0) { Fail "gradle buildExtension failed (exit $LASTEXITCODE)" }
}

# --- 4. Newest dist zip ---------------------------------------------------
# Match broadly on ghidra_*.zip: the zip's trailing name component is the gradle project name,
# which defaults to the checkout directory's basename -- so it is NOT 'ghidra-retro-machines'
# in a differently-named git worktree. dist/ only ever holds this extension's output.
$zip = Get-ChildItem (Join-Path $repoRoot 'dist/ghidra_*.zip') -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $zip) { Fail "no dist zip found in $repoRoot/dist (run without -SkipBuild)" }
Step "newest dist zip: $($zip.Name) ($($zip.LastWriteTime.ToString('yyyy-MM-dd HH:mm')), $([math]::Round($zip.Length/1MB,1)) MB)"

# --- 5. Resolve the GUI Extensions dir ------------------------------------
# ApplicationUtilities.getDefaultUserSettingsDir: <base>/<userdir>/<versionedName>, where
# versionedName = lowercase(application.name)_<version>_<release.name> read from the install's
# application.properties (NOT hardcoded), and userdir is plain "ghidra" when <base> is inside
# the user's home dir. For the GUI, base is %APPDATA%, which always is -- hence no
# "<username>-ghidra" branch here, unlike build-and-test.sh whose base sits inside the repo
# (build/ghidra-home) and so is generally outside the user's home dir.
if (-not $env:APPDATA) { Fail 'APPDATA is not set -- run this from Windows PowerShell/pwsh, not a Linux pwsh.' }

$props = @{}
foreach ($line in Get-Content $appProps) {
    if ($line -match '^([^=#]+)=(.*)$') { $props[$Matches[1].Trim()] = $Matches[2].Trim() }
}
foreach ($k in 'application.name', 'application.version', 'application.release.name') {
    if (-not $props[$k]) { Fail "could not parse $k from $appProps" }
}
$versionedName = "$($props['application.name'].ToLower())_$($props['application.version'])_$($props['application.release.name'])"

$extDir = Join-Path $env:APPDATA "ghidra/$versionedName/Extensions"
# Always install under the canonical name, whatever the zip's top-level dir is called, so a
# build from a renamed worktree updates the one GUI install instead of creating a second
# extension beside it.
$target = Join-Path $extDir 'ghidra-retro-machines'
Step "installing into $target"

# --- 6. Destructive install ----------------------------------------------
# Staged unzip then move, so a corrupt/short zip fails BEFORE the existing install is deleted.
if (-not $PSCmdlet.ShouldProcess($target, "Delete and replace with $($zip.Name)")) {
    $existing = if (Test-Path $target) { "present" } else { "absent" }
    Write-Host ""
    Write-Host "-WhatIf: would replace the extension (currently $existing) at" -ForegroundColor Yellow
    Write-Host "  $target"
    Write-Host "  from $($zip.FullName)"
    return
}

$staging = Join-Path ([System.IO.Path]::GetTempPath()) "grm-install-$(New-Guid)"
try {
    Expand-Archive -LiteralPath $zip.FullName -DestinationPath $staging -Force
    $srcDir = @(Get-ChildItem $staging -Directory)
    if ($srcDir.Count -ne 1) { Fail "unexpected dist zip layout: expected one top-level dir, found $($srcDir.Count)" }

    New-Item -ItemType Directory -Path $extDir -Force | Out-Null
    if (Test-Path $target) { Remove-Item $target -Recurse -Force }
    Move-Item $srcDir[0].FullName $target
}
finally {
    if (Test-Path $staging) { Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue }
}

if (-not (Test-Path (Join-Path $target 'extension.properties'))) {
    Fail "sanity check failed: no extension.properties under $target"
}

$jar = Get-ChildItem (Join-Path $target 'lib/*.jar') -ErrorAction SilentlyContinue | Select-Object -First 1
Write-Host ""
Write-Host "Installed $($zip.Name)" -ForegroundColor Green
if ($jar) { Write-Host "  jar:    $($jar.Name)  ($($jar.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" }
Write-Host "  target: $target"
Write-Host "Restart Ghidra to pick it up." -ForegroundColor Yellow
