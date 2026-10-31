#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
Install for the current administrator's interactive Windows session. -WhatIf previews only.
The Python 3.12+ runtime must be installed machine-wide and remain available after installation.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)][uri]$ServerUrl,
    [Parameter(Mandatory = $true)][string]$PythonExe,
    [switch]$EnableResponses,
    [switch]$EnableAuditPolicy,
    [switch]$StartNow
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$taskName = 'ShadowTrace Agent'
$installRoot = Join-Path $env:ProgramFiles 'ShadowTrace'
$dataRoot = Join-Path $env:ProgramData 'ShadowTrace'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\agent'))
$pythonPath = (Resolve-Path -LiteralPath $PythonExe).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if ($ServerUrl.Scheme -notin @('http', 'https') -or $ServerUrl.UserInfo -or $ServerUrl.Query -or
    $ServerUrl.Fragment -or $ServerUrl.AbsolutePath -ne '/') {
    throw 'ServerUrl must be an HTTP(S) origin without credentials, query or path.'
}
if ($ServerUrl.Scheme -eq 'http' -and -not $ServerUrl.IsLoopback) {
    throw 'Use HTTPS for a remote server. HTTP is supported only for a localhost demo.'
}
if (Test-Path -LiteralPath $installRoot) {
    throw "Install directory already exists: $installRoot. Use the existing installation or a clean host."
}
if (Test-Path -LiteralPath $dataRoot) {
    throw "Data directory already exists: $dataRoot. Preserve it and use the manual setup for this host."
}
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    throw 'The ShadowTrace scheduled task already exists.'
}
if (-not $PSCmdlet.ShouldProcess($installRoot,
    "Install agent, enroll interactively, and register a logon task for $($identity.Name)")) {
    return
}

function New-ProtectedDirectory([string]$Directory) {
    New-Item -ItemType Directory -Path $Directory | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $principal = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Directory -AclObject $acl
}

New-ProtectedDirectory $installRoot
New-ProtectedDirectory $dataRoot
$packageRoot = Join-Path $installRoot 'package'
New-Item -ItemType Directory -Path $packageRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $sourceRoot 'pyproject.toml') -Destination $packageRoot
Copy-Item -LiteralPath (Join-Path $sourceRoot 'shadowtrace_agent') -Destination $packageRoot -Recurse
$venvRoot = Join-Path $installRoot 'venv'
& $pythonPath -m venv --copies $venvRoot
if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed (Python 3.12+ required).' }
$agentPython = Join-Path $venvRoot 'Scripts\python.exe'
& $agentPython -m pip install $packageRoot
if ($LASTEXITCODE -ne 0) { throw 'Agent dependency installation failed.' }
$configPath = Join-Path $dataRoot 'config.yaml'
@'
import sys
from pathlib import Path
import yaml
source, dest, server, data, responses = sys.argv[1:]
config = yaml.safe_load(Path(source).read_text(encoding='utf-8'))
config.update(server_url=server.rstrip('/'), data_dir=data, enrollment_token=None)
config['responses']['enabled'] = responses.lower() == 'true'
Path(dest).write_text(yaml.safe_dump(config, sort_keys=False), encoding='utf-8')
'@ | & $agentPython - (Join-Path $sourceRoot 'config.example.yaml') $configPath `
    $ServerUrl.AbsoluteUri $dataRoot $EnableResponses.IsPresent.ToString()
if ($LASTEXITCODE -ne 0) { throw 'Configuration generation failed.' }

$secureToken = Read-Host 'Single-use enrollment token' -AsSecureString
try {
    # The token is passed over stdin, never in a process command line or the saved config.
    $credential = New-Object System.Net.NetworkCredential('', $secureToken)
    $credential.Password | & $agentPython -m shadowtrace_agent -c $configPath enroll --token-stdin
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment failed; task has not been registered.' }
} finally {
    $credential = $null
    $secureToken.Dispose()
}

if ($EnableAuditPolicy) {
    $auditBackup = Join-Path $dataRoot 'audit-policy-before.csv'
    & auditpol.exe /backup "/file:$auditBackup"
    if ($LASTEXITCODE -ne 0) { throw 'Audit policy backup failed.' }
    # Language-independent IDs: logon, logoff, lockout, user accounts, security groups.
    foreach ($id in @('9215', '9216', '9217', '9235', '9237')) {
        $subcategory = '{0CCE' + $id + '-69AE-11D9-BED3-505054503030}'
        & auditpol.exe /set "/subcategory:$subcategory" /success:enable /failure:enable
        if ($LASTEXITCODE -ne 0) { throw "Audit policy update failed for $subcategory" }
    }
}

$arguments = '-m shadowtrace_agent -c "' + $configPath + '" run'
$backgroundPython = Join-Path $venvRoot 'Scripts\pythonw.exe'
$action = New-ScheduledTaskAction -Execute $backgroundPython -Argument $arguments -WorkingDirectory $installRoot
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
$principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description 'ShadowTrace endpoint monitor' | Out-Null
if ($StartNow) { Start-ScheduledTask -TaskName $taskName }
Write-Output "Installed for $($identity.Name). Config: $configPath"
Write-Output "Starts at this user's next logon. Use -StartNow to start immediately."
