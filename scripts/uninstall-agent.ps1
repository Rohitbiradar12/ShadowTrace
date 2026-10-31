#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true)]
param()
$ErrorActionPreference = 'Stop'
$task = Get-ScheduledTask -TaskName 'ShadowTrace Agent' -ErrorAction SilentlyContinue
if ($task -and $PSCmdlet.ShouldProcess('ShadowTrace Agent', 'Stop and remove scheduled task')) {
    Stop-ScheduledTask -InputObject $task
    Unregister-ScheduledTask -InputObject $task -Confirm:$false
    Write-Output 'Task removed. Installation, configuration and forensic data are retained.'
    Write-Output 'Audit policy is unchanged; review audit-policy-before.csv before any restoration.'
}
