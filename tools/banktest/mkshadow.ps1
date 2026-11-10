# Build a junction-shadow Ghidra install so a candidate decompile.exe can be A/B-ed without touching
# the shared install (grm-gipk.25; bd memory decompiler-ab-via-junction-shadow-install, which has
# the two traps this layout avoids: Ghidra/Framework/Utility/lib must be a REAL directory, and
# never let gradle build against a shadow). Run in PowerShell.
#
# Usage: pwsh tools/banktest/mkshadow.ps1 -Shadow <new dir> -Exe <decompile.exe> [-Real <install>]
#   -Real defaults to $env:GRM_GHIDRA_INSTALL (the real Ghidra install dir).
#   -Shadow should not exist yet (build a fresh sibling rather than deleting an old shadow).
# Then run a tier with GHIDRA_HEADLESS=<shadow>/support/analyzeHeadless.bat
# GRM_GHIDRA_INSTALL=<shadow> GHIDRA_INSTALL_DIR= ... --no-build, after staging the extension
# against the REAL install, and verify with tools/banktest/WhichDecompiler.java.
param([string]$Real = $env:GRM_GHIDRA_INSTALL, [Parameter(Mandatory)][string]$Shadow,
  [Parameter(Mandatory)][string]$Exe)
if (-not $Real) { throw 'pass -Real or set GRM_GHIDRA_INSTALL' }
$ErrorActionPreference = 'Stop'
# Directories (relative) that must be REAL directories; everything else is junctioned.
$realDirs = @('', 'Ghidra', 'Ghidra/Features', 'Ghidra/Features/Decompiler',
  'Ghidra/Features/Decompiler/os', 'Ghidra/Features/Decompiler/os/win_x86_64',
  'Ghidra/Framework', 'Ghidra/Framework/Utility', 'Ghidra/Framework/Utility/lib')
foreach ($rel in $realDirs) {
  $src = if ($rel) { Join-Path $Real $rel } else { $Real }
  $dst = if ($rel) { Join-Path $Shadow $rel } else { $Shadow }
  New-Item -ItemType Directory -Force -Path $dst | Out-Null
  foreach ($c in Get-ChildItem -Force -LiteralPath $src) {
    $childRel = if ($rel) { "$rel/$($c.Name)" } else { $c.Name }
    $target = Join-Path $dst $c.Name
    if (Test-Path -LiteralPath $target) { continue }
    if ($c.PSIsContainer) {
      if ($realDirs -contains $childRel) { continue }
      New-Item -ItemType Junction -Path $target -Target $c.FullName | Out-Null
    } else {
      Copy-Item -LiteralPath $c.FullName -Destination $target
    }
  }
}
Copy-Item -Force -LiteralPath $Exe -Destination (Join-Path $Shadow 'Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe')
Write-Output "shadow ready: $Shadow"
