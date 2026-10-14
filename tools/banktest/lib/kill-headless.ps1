# Kills the headless Ghidra processes of ONE banktest run, identified by a unique string in their
# command line (bead grm-w9ev.5). Called by run-banktest.sh's timeout watchdog.
#
#   kill-headless.ps1 -Needle <path> [-DryRun]
#
# Why not `taskkill /T /PID <pid>`: /T selects "children" by their recorded ParentProcessId, which
# Windows never clears when a parent exits. A reused PID therefore makes unrelated processes look
# like children, and a whole-tree kill can reach them (an earlier draft of this watchdog is
# suspected of killing the agent session that ran it). Instead, match only java.exe/cmd.exe
# whose command line contains the run's own project directory. That directory is under a per-run
# mktemp $WORK, so nothing outside this run can carry it: not another worktree's Ghidra, not a
# Gradle daemon, not the shell that called us.
#
# Matching ignores case and slash direction, so the needle matches whether a launcher passes the
# path as D:/a/b or D:\a\b. Each matched process is killed by its own PID, with no tree walk.
# -DryRun prints what would be killed and kills nothing.
param(
	[Parameter(Mandatory = $true)][string]$Needle,
	[switch]$DryRun
)

$norm = { param($s) $s.Replace('\', '/').ToLowerInvariant() }
$want = & $norm $Needle
if ($want.Length -lt 12) {
	# A short needle could match far too much; refuse rather than guess.
	Write-Output "KILL-HEADLESS: refusing short needle '$Needle'"
	exit 2
}

$hits = Get-CimInstance Win32_Process -Filter "Name = 'java.exe' OR Name = 'cmd.exe'" |
	Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and (& $norm $_.CommandLine).Contains($want) }

if (-not $hits) {
	Write-Output "KILL-HEADLESS: no process matches $Needle"
	exit 0
}
foreach ($p in $hits) {
	$verb = if ($DryRun) { 'would kill' } else { 'killing' }
	Write-Output ("KILL-HEADLESS: {0} pid={1} {2}: {3}" -f $verb, $p.ProcessId, $p.Name, $p.CommandLine)
	if (-not $DryRun) {
		Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
	}
}
