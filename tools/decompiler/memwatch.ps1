# Memory watchdog for experimental decompile.exe builds (grm-hf5h.8).
#
# A candidate decompiler with a looping heritage pass allocated until the host hit its commit
# limit (bash fork failed with 0xC000012D, STATUS_COMMITMENT_LIMIT) and the machine went down,
# three times in a row. Ghidra limits a decompile by time, not by memory, so nothing else stops
# it. Run this beside any gate or probe that launches an unproven decompile.exe: it kills every
# process named decompile whose private memory exceeds the cap and logs the kill.
#
# Usage (Windows PowerShell 5 or pwsh; in the background, before the gate starts):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools/decompiler/memwatch.ps1 [-CapGB 3] [-Log <file>] [-Minutes 120]
# A killed decompile.exe shows up in the tier as "Decompiler process died" for that function;
# check the log before reading such a row as a real crash.
param([double]$CapGB = 3, [string]$Log = "", [int]$Minutes = 120, [string]$Name = "decompile")
$cap = [long]($CapGB * 1GB)
$until = (Get-Date).AddMinutes($Minutes)
while ((Get-Date) -lt $until) {
  foreach ($p in Get-Process -Name $Name -ErrorAction SilentlyContinue) {
    if ($p.PrivateMemorySize64 -gt $cap) {
      $line = "{0:s} killed {1} pid={2} private={3:N1}GB cap={4}GB" -f (Get-Date), $p.Name, $p.Id,
        ($p.PrivateMemorySize64 / 1GB), $CapGB
      try { Stop-Process -Id $p.Id -Force -ErrorAction Stop } catch { $line += " (kill failed: $_)" }
      Write-Output $line
      if ($Log) { Add-Content -LiteralPath $Log -Value $line }
    }
  }
  Start-Sleep -Milliseconds 500
}
