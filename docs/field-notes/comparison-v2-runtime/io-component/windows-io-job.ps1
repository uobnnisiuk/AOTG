param([Parameter(Mandatory=$true)][string]$Plan)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# WSL may pass a Linux PSModulePath into Windows PowerShell. Use only the
# existing bundled modules in this process; never discover user modules.
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')

function FileHash([string]$Path) {
    $stream=[IO.File]::OpenRead($Path)
    $algorithm=[Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','').ToLowerInvariant() }
    finally { $algorithm.Dispose(); $stream.Dispose() }
}

# This trusted wrapper only accepts a previously frozen SSH invocation. It
# produces no stdout itself: stdout is an exact byte stream from ssh.exe.
$planPath = (Resolve-Path -LiteralPath $Plan).Path
$planBytes = [IO.File]::ReadAllBytes($planPath)
$planAlgorithm = [Security.Cryptography.SHA256]::Create()
try { $loadedPlanSha=[BitConverter]::ToString($planAlgorithm.ComputeHash($planBytes)).Replace('-','').ToLowerInvariant() }
finally { $planAlgorithm.Dispose() }
$frozen = [Text.Encoding]::UTF8.GetString($planBytes) | ConvertFrom-Json
$fields = @('artifact','version','wrapper_sha256','helper','executable','argv','cwd','wall_seconds','cancel_path','result_path')
if (@($frozen.PSObject.Properties.Name | Where-Object {$_ -notin $fields}).Count -or @($frozen.PSObject.Properties).Count -ne $fields.Count) {
    throw 'Invalid Windows SSH job plan fields'
}
if ($frozen.artifact -ne 'aotg-windows-io-job' -or $frozen.version -ne 2) { throw 'Unsupported Windows SSH job plan' }
if ((FileHash $PSCommandPath) -cne $frozen.wrapper_sha256) { throw 'SSH wrapper changed after freeze' }
if (-not [IO.Path]::IsPathRooted($frozen.helper.path)) { throw 'Absolute trusted helper path required' }
$helperBytes=[IO.File]::ReadAllBytes($frozen.helper.path)
$helperAlgorithm=[Security.Cryptography.SHA256]::Create()
try { $loadedHelperSha=[BitConverter]::ToString($helperAlgorithm.ComputeHash($helperBytes)).Replace('-','').ToLowerInvariant() }
finally { $helperAlgorithm.Dispose() }
if ($loadedHelperSha -cne $frozen.helper.sha256) { throw 'Trusted job helper hash mismatch' }
if (-not [IO.Path]::IsPathRooted($frozen.executable.path) -or [IO.Path]::GetFileName($frozen.executable.path) -cne 'ssh.exe') { throw 'Exact existing ssh.exe required' }
if ((FileHash $frozen.executable.path) -cne $frozen.executable.sha256) { throw 'Existing SSH hash mismatch' }
if ($frozen.wall_seconds -isnot [int] -or $frozen.wall_seconds -ne 6275) { throw 'Finite wall limit required' }
if (-not [IO.Path]::IsPathRooted($frozen.result_path) -or (Test-Path -LiteralPath $frozen.result_path)) { throw 'New explicit result path required' }
if (-not [IO.Path]::IsPathRooted($frozen.cancel_path) -or (Test-Path -LiteralPath $frozen.cancel_path)) { throw 'New explicit cancellation marker required' }
if (-not (Test-Path -LiteralPath $frozen.cwd -PathType Container)) { throw 'Existing owned cwd required' }
if (@($frozen.argv).Count -gt 128 -or '-T' -notin $frozen.argv -or 'BatchMode=yes' -notin $frozen.argv -or 'ForwardAgent=no' -notin $frozen.argv) { throw 'Explicit noninteractive SSH and agent forwarding disabled required' }

Add-Type -TypeDefinition ([Text.Encoding]::UTF8.GetString($helperBytes)) -Language CSharp
$result = $null
try {
    $result = [AotgWindowsIoJobV2]::Run($frozen.executable.path, $frozen.executable.sha256,
        [string[]]$frozen.argv, $frozen.cwd, [int]($frozen.wall_seconds * 1000), $frozen.cancel_path)
    $metadata = @{artifact='aotg-windows-io-job-result';version=2;plan_sha256=$loadedPlanSha;
        helper_sha256=$frozen.helper.sha256;wrapper_sha256=$frozen.wrapper_sha256;result=$result}
    $temporary = $frozen.result_path + '.tmp'
    if (Test-Path -LiteralPath $temporary) { throw 'Temporary result exists' }
    [IO.File]::WriteAllText($temporary, ($metadata | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $frozen.result_path
    if ($result.TimedOut -or $result.Cancelled) { exit 124 }
    exit ([int]$result.ExitCode)
} catch {
    # Errors contain operation names and native error codes, never SSH stdin or
    # credential material. Job helper finally/kill-on-close owns native cleanup.
    [Console]::Error.WriteLine('Owned Windows SSH job failed: ' + $_.Exception.GetType().Name)
    exit 125
}
