# Runs ExportFunctions.java via analyzeHeadless (Windows).
#
# Usage:
#   $env:GHIDRA_HOME = "C:\path\to\ghidra_12.1_PUBLIC"
#   .\ghidra_scripts\run_headless_export.ps1 re_test_target.exe data\input\re_test_target.jsonl
#
# Or pass Ghidra path explicitly:
#   .\ghidra_scripts\run_headless_export.ps1 re_test_target.exe data\input\out.jsonl `
#       -GhidraHome "C:\path\to\ghidra_12.1_PUBLIC"

param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Binary,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$Output,

    [string]$GhidraHome
)

if ($GhidraHome) {
    $env:GHIDRA_HOME = $GhidraHome
}

if (-not $env:GHIDRA_HOME) {
    Write-Error @"
GHIDRA_HOME is not set.

In PowerShell:
  `$env:GHIDRA_HOME = 'C:\path\to\ghidra_12.1_PUBLIC'

Then re-run this script, or pass -GhidraHome.
"@
    exit 1
}

$bat = Join-Path $PSScriptRoot "run_headless_export.bat"
if (-not (Test-Path $bat)) {
    Write-Error "Not found: $bat"
    exit 1
}

& $bat $Binary $Output
exit $LASTEXITCODE
