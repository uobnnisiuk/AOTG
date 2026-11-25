param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
$helper=Join-Path $PSScriptRoot 'WindowsIoJobV2.cs'
$source=[IO.File]::ReadAllText($helper)
$hash=[Security.Cryptography.SHA256]::Create()
try { $helperSha=[BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($helper))).Replace('-','').ToLowerInvariant() }
finally {$hash.Dispose()}
Add-Type -TypeDefinition $source -Language CSharp
$exe=[IO.Path]::Combine($PSHOME,'powershell.exe')
$hash=[Security.Cryptography.SHA256]::Create()
try { $exeSha=[BitConverter]::ToString($hash.ComputeHash([IO.File]::ReadAllBytes($exe))).Replace('-','').ToLowerInvariant() }
finally {$hash.Dispose()}
if(Test-Path -LiteralPath $Output){throw 'Exclusive fixture output required'}
$timeout=[AotgWindowsIoJobV2]::Run($exe,$exeSha,
    [string[]]@('-NoLogo','-NoProfile','-NonInteractive','-Command','[Threading.Thread]::Sleep(30000)'),
    $PSScriptRoot,200,$null)
if(-not $timeout.TimedOut -or -not $timeout.JobEmpty){throw 'Timeout fixture failed'}
$aboveOldCap=[AotgWindowsIoJobV2]::Run($exe,$exeSha,
    [string[]]@('-NoLogo','-NoProfile','-NonInteractive','-Command','exit 0'),
    $PSScriptRoot,2100001,$null)
if($aboveOldCap.TimedOut -or -not $aboveOldCap.JobEmpty -or $aboveOldCap.ExitCode -ne 0){throw 'Finite extended-cap fixture failed'}
$rejected=$false
try {
    [void][AotgWindowsIoJobV2]::Run($exe,$exeSha,[string[]]@(),$PSScriptRoot,6275001,$null)
} catch { $rejected=$true }
if(-not $rejected){throw 'Out-of-policy timeout accepted'}
$record=@{artifact='aotg-io-v2-native-fixtures';version=1;synthetic=$true;ssh_invoked=$false;
    sampler_invoked=$false;helper_sha256=$helperSha;executable_sha256=$exeSha;
    timeout=$timeout;above_old_cap_immediate_exit=$aboveOldCap;over_maximum_rejected=$rejected}
[IO.File]::WriteAllText($Output,($record | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))
Write-Output 'Three harmless native fixture checks passed; no SSH or counters read.'
