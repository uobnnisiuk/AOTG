param([string]$FixturePath,[string]$RecorderPath,[string]$RecorderSha256)
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$source=[IO.File]::ReadAllText($FixturePath)
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Rendered PS5 syntax errors'}
$entry=$source.IndexOf('# ENTRY:',[StringComparison]::Ordinal)
if($entry -lt 1){throw 'Missing isolated function boundary'}
# Dot-source only the literal pins and functions. The operational entry is excluded.
. ([ScriptBlock]::Create($source.Substring(0,$entry)))
if($env:PSModulePath -cne [IO.Path]::Combine($PSHOME,'Modules')){throw 'Child module path not repaired'}
Assert-PinnedFile $RecorderPath $RecorderSha256
Assert-AllPins
$wrongRejected=$false
try{Assert-PinnedFile $RecorderPath ('0'*64)}catch{$wrongRejected=$true}
if(!$wrongRejected){throw 'Wrong pinned hash accepted'}
$ApprovalPath='C:\fixture\approval.json'
if((Approval-WslPath) -cne '/mnt/c/fixture/approval.json'){throw 'C path conversion differs'}
$ApprovalPath='\\wsl.localhost\Ubuntu\home\fixture\approval.json'
if((Approval-WslPath) -cne '/home/fixture/approval.json'){throw 'UNC path conversion differs'}
$ApprovalPath='C:\fixture\..\approval.json'
$badPathRejected=$false
try{$null=Approval-WslPath}catch{$badPathRejected=$true}
if(!$badPathRejected){throw 'Traversal path accepted'}
$arguments=@($Pinned.ssh_args)
$lines=@(& $RecorderPath @arguments $Pinned.command)
if($LASTEXITCODE -ne 0 -or [int]$lines[0] -ne ($arguments.Count+1)){throw 'Harmless native recorder failed'}
for($i=0;$i -lt $arguments.Count;$i++){
 $actual=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($lines[$i+1]))
 if($actual -cne $arguments[$i]){throw 'Existing route changed across PS5 native boundary'}
}
$received=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($lines[-1]))
if($received -cne $Pinned.command){throw 'Numeric command changed across PS5 native boundary'}
# Actual Desktop cmdlet autoload after deliberately inheriting a PS7-only module path.
$null=Get-FileHash -LiteralPath $RecorderPath -Algorithm SHA256
[ordered]@{artifact='aotg-synthetic-ps5-window-functions';version=2;
 powershell_version=$PSVersionTable.PSVersion.ToString();syntax_valid=$true;
 pins_checked=$true;bad_pin_rejected=$wrongRejected;bad_path_rejected=$badPathRejected;
 child_module_path_repaired=$true;native_argv_equal=$true;
 native_command_utf8_base64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($received));
 ssh_started=$false;authentication_started=$false;production_touched=$false} | ConvertTo-Json -Compress
