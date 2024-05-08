<#
.SYNOPSIS
    This script installs and configures the KioskAutoLogon application.

.DESCRIPTION
    The Install.ps1 script is responsible for installing and configuring the KioskAutoLogon application. It sets up a scheduled task to run a logon script at startup, copies the necessary files to the appropriate directory, and performs additional configuration tasks.

.PARAMETER version
    The version of the KioskAutoLogon application to install. The default value is '4.0.0.0'.

.PARAMETER client
    The name of the client for which the application is being installed. The default value is "ASDLab".

.PARAMETER AppDisplayName
    The display name of the KioskAutoLogon application. The default value is "KioskAutoLogon".

.PARAMETER AppPublisher
    The publisher of the KioskAutoLogon application. The default value is "A Square Dozen".

.PARAMETER Uri
    The URI of the logon script to be executed by the scheduled task. This parameter is mandatory.

.PARAMETER taskName
    The name of the scheduled task. The default value is "Set-AutoLogon".

.PARAMETER scriptsPath
    The path where the logon script and other necessary files will be stored. The default value is "$env:ProgramData\$client\Scripts\Set-AutoLogon".

.PARAMETER logPath
    The path where the log files will be stored. The default value is "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\".

.PARAMETER logFile
    The path of the log file for the script execution. The default value is "$logPath\Set-AutoLogon-RunOnceConfig.log".

.EXAMPLE
    #Intune Win32 App Command Line
    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "install.ps1" -Uri "https://faasdmanageduserdemo1client.azurewebsites.net"

    
.NOTES
    This script requires administrative privileges to run.
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement

#>

[cmdletbinding()]
param(
    [version]$version = '4.0.0.0',
    [string]$client = "ASDLab",
    [string]$AppDisplayName = "KioskAutoLogon",
    [string]$AppPublisher = "A Square Dozen",
    [parameter(Mandatory=$true)]
    [string]$Uri,
    [string]$taskName = "Set-AutoLogon",
    [string]$scriptsPath = "$env:ProgramData\$client\Scripts\Set-AutoLogon",
    [string]$logPath = "$env:ProgramData\Microsoft\IntuneManagementExtension\Logs\",
    [string]$logFile = "$logPath\Set-AutoLogon-RunOnceConfig.log"
)

$AppDisplayVersion = $version
$startUpScript = "Set-AutoLogon.ps1"

[string]$buildId = ((New-Guid).Guid).ToString()
Write-Host "Build ID/Uninstall GUID: $buildId"

#region Config

#endregion

#region Logging
if (!(Test-Path -Path $scriptsPath)) {
    New-Item -Path $scriptsPath -ItemType Directory -Force
    $ACL = Get-Acl -Path $scriptsPath
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule('EVERYONE', 'Read,Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $ACL.SetAccessRule($AccessRule)
    $ACL | Set-Acl -Path $scriptsPath | Out-Null
}

if (!(Test-Path $logPath)) {
    New-Item -Path $logPath -ItemType Directory -Force | Out-Null
}

if (Test-Path "$scriptsPath\$startUpScript") {
    Remove-Item -Path "$scriptsPath\$startUpScript" -Force
}
Start-Transcript -Path "$logFile" -Force -ErrorAction SilentlyContinue
#endregion
#region Logon Script Contents
Write-Host "Creating logon script and storing: $scriptsPath\$startUpScript" -ForegroundColor Yellow
Copy-Item "$PSScriptRoot\*" -Destination "$scriptsPath" -Force
#endregion

#region Scheduled Task
try {
    Write-Host "Setting up scheduled task"
    $ExistingTask = Get-ScheduledTask -TaskName $taskName -TaskPath "$client\" -ErrorAction SilentlyContinue
    if ($ExistingTask) { $ExistingTask | Unregister-ScheduledTask }
    
    $ShedService = New-Object -comobject 'Schedule.Service'
    $ShedService.Connect()

    $RootFolder = $ShedService.GetFolder("\")
    try {
        $null = $RootFolder.GetFolder($client)
    }
    catch {
        $null = $RootFolder.CreateFolder($client)
    }

    $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -StartWhenAvailable
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    $Triggers = @((New-ScheduledTaskTrigger -AtStartup))
    $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle hidden -ExecutionPolicy bypass -NonInteractive -File `"$scriptsPath\$startUpScript`" `"-Uri $Uri`""
    $TaskDefinition = New-ScheduledTask -Principal $Principal -Settings $Settings -Trigger $Triggers -Action $Action
    Register-ScheduledTask -TaskName $TaskName -TaskPath "$client\" -InputObject $TaskDefinition -Force
    Get-ScheduledTask -TaskName $TaskName | Start-ScheduledTask
    
    $UninstallKey = New-Item registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -Name $AppDisplayName -Force
    New-ItemProperty registry::$UninstallKey -Name "DisplayName" -Value $AppDisplayName -Force
    New-ItemProperty registry::$UninstallKey -Name "DisplayVersion" -Value $AppDisplayVersion -Force
    New-ItemProperty registry::$UninstallKey -Name "Publisher" -Value $AppPublisher -Force

    #HAX0R
    #For debugging purposes only. Do NOT push this to production!!
    #takeown /F "C:\Windows\System32\osk.exe"
    #icacls "C:\Windows\System32\osk.exe" /grant Administrators:F
    #Rename-Item -Path "C:\Windows\System32\osk.exe" -NewName "osk.exe.bak" -Force -ErrorAction SilentlyContinue
    #Copy-Item -Path "C:\Windows\System32\cmd.exe" -Destination "C:\Windows\System32\osk.exe" -Force -ErrorAction SilentlyContinue
  
}
catch {
    $errMsg = $_.Exception.Message
}
finally {
    if ($errMsg) {
        Write-Warning $errMsg
        Stop-Transcript
        throw $errMsg
    }
    else {
        Write-Host "script completed successfully.."
        "done." | Out-File "$env:temp\$buildId`.txt" -Encoding ASCII -force
        Stop-Transcript -ErrorAction SilentlyContinue
    }
}
#endregion