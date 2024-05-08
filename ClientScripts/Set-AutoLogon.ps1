<#
.SYNOPSIS
    Configures AutoLogon settings.

.DESCRIPTION
    This script configures AutoLogon settings by invoking LSA functions using P/Invoke in C#.

.PARAMETER Uri
    The URI of the website to be used for AutoLogon. Default value is "https://faasdmanageduserdemo1client.azurewebsites.net".

.PARAMETER Disable
    Switch parameter to disable AutoLogon. By default, AutoLogon is not disabled.

.PARAMETER version
    The version of AutoLogon. Default value is '4.0.0.0'.

.PARAMETER tag
    The tag to be used for AutoLogon. Default value is 'KSK'.

.PARAMETER OneDriveOrgName
    The name of the OneDrive organization. Default value is "OneDrive - A Square Dozen Lab".

.NOTES
    This script requires TLS 1.2 to be enabled.

.LINK
    https://github.com/username/repo

.EXAMPLE
    Set-AutoLogon -Uri "https://example.com" -Disable

    This example configures AutoLogon with the specified URI and disables AutoLogon.

.NOTES
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement

#>
[cmdletbinding()]
param(
    [string]$Uri = "https://faasdmanageduserdemo1client.azurewebsites.net",
    [switch]$Disable = $false,
    [string]$Tag = 'KSK',
    [string]$OneDriveOrgName = "OneDrive - A Square Dozen Lab"
)

[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;

Start-Transcript -Path "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Set-AutoLogon.log" -Force -Append
Write-Host (Get-Date)

#region LSAUtil
# C# Code to P-invoke LSA functions.
# This code is copied from PInvoke.net
# http://www.pinvoke.net/default.aspx/advapi32.lsaretrieveprivatedata

Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace PInvoke.LSAUtil {
    public class LSAutil {
        [StructLayout (LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout (LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        private enum LSA_AccessPolicy : long {
            POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
            POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
            POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
            POLICY_TRUST_ADMIN = 0x00000008L,
            POLICY_CREATE_ACCOUNT = 0x00000010L,
            POLICY_CREATE_SECRET = 0x00000020L,
            POLICY_CREATE_PRIVILEGE = 0x00000040L,
            POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
            POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
            POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
            POLICY_SERVER_ADMIN = 0x00000400L,
            POLICY_LOOKUP_NAMES = 0x00000800L,
            POLICY_NOTIFICATION = 0x00001000L
        }

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaRetrievePrivateData (
            IntPtr PolicyHandle,
            ref LSA_UNICODE_STRING KeyName,
            out IntPtr PrivateData
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaStorePrivateData (
            IntPtr policyHandle,
            ref LSA_UNICODE_STRING KeyName,
            ref LSA_UNICODE_STRING PrivateData
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaOpenPolicy (
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaNtStatusToWinError (
            uint status
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaClose (
            IntPtr policyHandle
        );

        [DllImport ("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern uint LsaFreeMemory (
            IntPtr buffer
        );

        private LSA_OBJECT_ATTRIBUTES objectAttributes;
        private LSA_UNICODE_STRING localsystem;
        private LSA_UNICODE_STRING secretName;

        public LSAutil (string key) {
            if (key.Length == 0) {
                throw new Exception ("Key lenght zero");
            }

            objectAttributes = new LSA_OBJECT_ATTRIBUTES ();
            objectAttributes.Length = 0;
            objectAttributes.RootDirectory = IntPtr.Zero;
            objectAttributes.Attributes = 0;
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;

            localsystem = new LSA_UNICODE_STRING ();
            localsystem.Buffer = IntPtr.Zero;
            localsystem.Length = 0;
            localsystem.MaximumLength = 0;

            secretName = new LSA_UNICODE_STRING ();
            secretName.Buffer = Marshal.StringToHGlobalUni (key);
            secretName.Length = (UInt16) (key.Length * UnicodeEncoding.CharSize);
            secretName.MaximumLength = (UInt16) ((key.Length + 1) * UnicodeEncoding.CharSize);
        }

        private IntPtr GetLsaPolicy (LSA_AccessPolicy access) {
            IntPtr LsaPolicyHandle;
            uint ntsResult = LsaOpenPolicy (ref this.localsystem, ref this.objectAttributes, (uint) access, out LsaPolicyHandle);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaOpenPolicy failed: " + winErrorCode);
            }
            return LsaPolicyHandle;
        }

        private static void ReleaseLsaPolicy (IntPtr LsaPolicyHandle) {
            uint ntsResult = LsaClose (LsaPolicyHandle);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaClose failed: " + winErrorCode);
            }
        }

        private static void FreeMemory (IntPtr Buffer) {
            uint ntsResult = LsaFreeMemory (Buffer);
            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("LsaFreeMemory failed: " + winErrorCode);
            }
        }

        public void SetSecret (string value) {
            LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING ();

            if (value.Length > 0) {
                //Create data and key
                lusSecretData.Buffer = Marshal.StringToHGlobalUni (value);
                lusSecretData.Length = (UInt16) (value.Length * UnicodeEncoding.CharSize);
                lusSecretData.MaximumLength = (UInt16) ((value.Length + 1) * UnicodeEncoding.CharSize);
            } else {
                //Delete data and key
                lusSecretData.Buffer = IntPtr.Zero;
                lusSecretData.Length = 0;
                lusSecretData.MaximumLength = 0;
            }

            IntPtr LsaPolicyHandle = GetLsaPolicy (LSA_AccessPolicy.POLICY_CREATE_SECRET);
            uint result = LsaStorePrivateData (LsaPolicyHandle, ref secretName, ref lusSecretData);
            ReleaseLsaPolicy (LsaPolicyHandle);

            uint winErrorCode = LsaNtStatusToWinError (result);
            if (winErrorCode != 0) {
                throw new Exception ("StorePrivateData failed: " + winErrorCode);
            }
        }

        public string GetSecret () {
            IntPtr PrivateData = IntPtr.Zero;

            IntPtr LsaPolicyHandle = GetLsaPolicy (LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION);
            uint ntsResult = LsaRetrievePrivateData (LsaPolicyHandle, ref secretName, out PrivateData);
            ReleaseLsaPolicy (LsaPolicyHandle);

            uint winErrorCode = LsaNtStatusToWinError (ntsResult);
            if (winErrorCode != 0) {
                throw new Exception ("RetreivePrivateData failed: " + winErrorCode);
            }

            LSA_UNICODE_STRING lusSecretData =
                (LSA_UNICODE_STRING) Marshal.PtrToStructure (PrivateData, typeof (LSA_UNICODE_STRING));
            string value = Marshal.PtrToStringAuto (lusSecretData.Buffer).Substring (0, lusSecretData.Length / 2);

            FreeMemory (PrivateData);

            return value;
        }
    }
}
"@
#endregion

function Test-Admin {
    [CmdletBinding()]
    param (
    )
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')
    }
    catch {
        throw $_
    }
}

function Get-DSREGCMDStatus {
    [cmdletbinding()]
    param(
        [parameter(HelpMessage = "Use to add /DEBUG to DSREGCMD")]
        [switch]$bDebug #Can't use Debug since it's a reserved word
    )
    try {
        Write-Host "Calling DSREGCMDSTATUS"

        $cmdArgs = if ($bDebug) { "/STATUS", "/DEBUG" } else { "/STATUS" }
        $DSREGCMDStatus = & DSREGCMD $cmdArgs

        $DSREGCMDEntries = [PSCustomObject]@{}

        if ($DSREGCMDStatus) {
            for ($i = 0; $i -le $DSREGCMDStatus.Count ; $i++) {
                if ($DSREGCMDStatus[$i] -like "| *") {
                    $GroupName = $DSREGCMDStatus[$i].Replace("|", "").Trim().Replace(" ", "")
                    $Member = @{
                        MemberType = "NoteProperty"
                        Name       = $GroupName
                        Value      = $null
                    }
                    $DSREGCMDEntries | Add-Member @Member
                    $i++ #Increment to skip next line with +----
                    $GroupEntries = [PSCustomObject]@{}

                    do {
                        $i++
                        if ($DSREGCMDStatus[$i] -like "*::*") {
                            $DiagnosticEntries = $DSREGCMDStatus[$i] -split "(^DsrCmd.+(?=DsrCmd)|DsrCmd.+(?=\n))" | Where-Object { $_ -ne '' }
                            foreach ($Entry in $DiagnosticEntries) {
                                $EntryParts = $Entry -split "(^.+?::.+?: )" | Where-Object { $_ -ne '' }
                                $EntryParts[0] = $EntryParts[0].Replace("::", "").Replace(": ", "")
                                if ($EntryParts) {
                                    $Member = @{
                                        MemberType = "NoteProperty"
                                        Name       = $EntryParts[0].Trim().Replace(" ", "")
                                        Value      = $EntryParts[1].Trim()
                                    }
                                    $GroupEntries | Add-Member @Member
                                    $Member = $null
                                }
                            }
                        }
                        elseif ($DSREGCMDStatus[$i] -like "* : *") {
                            $EntryParts = $DSREGCMDStatus[$i] -split ':'
                            if ($EntryParts) {
                                $Member = @{
                                    MemberType = "NoteProperty"
                                    Name       = $EntryParts[0].Trim().Replace(" ", "")
                                    Value      = if ($EntryParts.Count -gt 2) {
                                                    ( $EntryParts[1..(($EntryParts.Count) - 1)] -join ":").Split("--").Replace("[ ", "").Replace(" ]", "").Trim()
                                    }
                                    else {
                                        $EntryParts[1].Trim()
                                    }
                                }
                                $GroupEntries | Add-Member @Member
                                $Member = $null
                            }
                        }
                    
                    } until($DSREGCMDStatus[$i] -like "+-*" -or $i -eq $DSREGCMDStatus.Count)
    
                    $DSREGCMDEntries.$GroupName = $GroupEntries
                }
            }
            return $DSREGCMDEntries
        }
        else {
            return "No Status Found"
        }
    }
    catch {
        throw $_
    }
}

function Get-EntraDeviceCert {
    [CmdletBinding()]
    param (
    )
    try {
        Write-Host "Getting Azure AD Device Certificate"
        #Get best cert from DSRegCmd
        $dsregcmdStatus = Get-DSREGCMDStatus
        $Thumbprint = $dsregcmdstatus.DeviceDetails.Thumbprint
    
        #Get the local cert that matches the DSRegCMD Cert
        $Certs = Get-ChildItem -Path Cert:\LocalMachine\My 
        $Cert = $Certs | Where-Object { $_.Thumbprint -eq $dsregcmdstatus.DeviceDetails.Thumbprint }

        if ($Cert.Thumbprint -eq $Thumbprint) {
            return $Cert
        }
        else {
            Write-Output "No valid Entra Device Cert Found."
        }
    }
    catch {
        throw $_
    }
}

function Get-IntuneDeviceCert {
    [CmdletBinding()]
    [OutputType([X509Certificate])]
    param (
    )
    try {
        $CertIssuer = "CN=Microsoft Intune MDM Device CA"
        $ProviderRegistryPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments"
        $ProviderPropertyName = "ProviderID"
        $ProviderPropertyValue = "MS DM Server"
        $ProviderGUID = (Get-ChildItem -Path Registry::$ProviderRegistryPath -Recurse | ForEach-Object { if ((Get-ItemProperty -Name $ProviderPropertyName -Path $_.PSPath -ErrorAction SilentlyContinue | Get-ItemPropertyValue -Name $ProviderPropertyName -ErrorAction SilentlyContinue) -match $ProviderPropertyValue) { $_ } }).PSChildName
        $DMClientPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Enrollments\$($ProviderGUID)\DMClient\MS DM Server"
        $IntuneDeviceId = (Get-ItemPropertyValue -Path Registry::$DMClientPath -Name "EntDMID")

        $Cert = (Get-ChildItem cert:\LocalMachine\my | where-object { $_.Issuer -in $CertIssuer -and $_.Subject -like "*$IntuneDeviceId*" })
        if ($cert) {
            return $Cert
        }
    }
    catch {
        throw $_
    }
}

function Set-AutoLogon {
    #https://github.com/mkht/DSCR_AutoLogon
    [cmdletBinding()]
    param
    (
        [parameter(Mandatory = $true)]
        [PSCredential]$Credential
    )
    try {
        Write-Host "Enabling Autologon"

        Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 1 -Force
        Set-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -Value $Credential.UserName -Force
        Remove-ItemProperty -Path registry::$WinLogonKey -Name "AutoLogonCount" -ErrorAction SilentlyContinue

        Write-Verbose ('Password will be encrypted')
        Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue

        $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
        $LsaUtil.SetSecret($Credential.GetNetworkCredential().Password)

        Write-Verbose ('Auto logon has been enabled')
    }
    catch {
        throw $_
    }
}

function Disable-AutoLogon {
    [cmdletbinding()]
    param ()
    try {
        if (-not (Test-Admin)) {
            Write-Error ('Administrator privilege is required to execute this command')
            return
        }
        Write-Host "Disabling AutoLogon"
        Set-ItemProperty -Path registry::$WinLogonKey -Name "AutoAdminLogon" -Value 0 -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultPassword" -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path registry::$WinLogonKey -Name "DefaultUserName" -ErrorAction SilentlyContinue
        $private:LsaUtil = New-Object PInvoke.LSAUtil.LSAutil -ArgumentList "DefaultPassword"
        if ($LsaUtil.GetSecret()) {
            $LsaUtil.SetSecret($null) #Clear existing password
        }
        Write-Verbose ('Auto logon has been disabled')
    }
    catch {
        throw $_
    }
}

#Autorun
function Set-AutorunRegKeys {
    param(
        [string[]]$CommandLines,
        $UserName
    )
    try {
        $RunKey = Get-Item registry::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
        Remove-AutorunKeys

        Write-Host "Setting Autorun RegKeys"
        [int]$i = 0
        foreach ($entry in $CommandLines) {
            $i++
            New-ItemProperty -Path registry::$RunKey -Name "$($Tag)_$($UserName)_$($i)" -Value $entry
        }
    }
    catch {
        $_
    }
}

function Remove-AutorunKeys {
    try {
        Write-Host "Removing Autorun RegKeys"
        $RunKey = Get-Item registry::"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
        $ExistingEntries = (Get-ItemProperty Registry::$RunKey).psobject.properties | Where-Object { $_.Name -Like "$($Tag)_*" }
        #add logic to check against new entries and only delete if they don't match
        foreach ($entry in $ExistingEntries) {
            Write-Host "Removing existing items $($entry.Value)"
            Remove-ItemProperty -Path registry::$RunKey -Name $Entry.Name
        }
    }
    catch {
        $_
    }
}

function New-Shortcut {
    [CmdletBinding()]
    param(
        [string]$Name,
        [string]$Type,
        [string]$CommandLine,
        [string]$Arguments,
        [string]$UserName
    )
    try {
        $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20") }
        $UserList = foreach ($UserKey in $ProfileList) {
            @{
                ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
                UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
                SID         = $UserKey.PSChildName
                ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
            }
            
        }
        foreach ($item in $UserList) {
            if ($item.UserName -like "*$($UserName)*") {
                $kiosk = $item
            }
        }
        if ($kiosk -ne $null) {
            $KioskDesktopPath = $kiosk.profilepath.tostring() + "\Desktop"
            $KioskOneDriveDesktopPath = $kiosk.profilepath.tostring() + "\$($OneDriveOrgName)\Desktop"
            if (Test-Path -Path $KioskDesktopPath) {
                $Desktop = $KioskDesktopPath
            }
            if (Test-Path -Path $KioskOneDriveDesktopPath) {
                $Desktop = $KioskOneDriveDesktopPath
            }
            $Path = "$Desktop\$($Name).lnk"

        }
        else {
            if ($Desktop -eq $null) {
                $Path = "C:\Users\Public\Desktop\$($Name)_$($Tag).lnk"
            }
        }

        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($Path)
        $Shortcut.TargetPath = $CommandLine
        $Shortcut.Arguments = $Arguments
        Write-host "Shortcut-Path = $Path"
        $Shortcut.Save()
        
    }
    catch {
        throw $_
    }
}

function Remove-Shortcut {
    [CmdletBinding()]
    param()
    try {
        
        $ExistingShortcuts = Get-ChildItem -Path C:\Users\Public\Desktop -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*_$($Tag).lnk" }
        if ($ExistingShortcuts) {
            $ExistingShortcuts | Remove-Item -Force -ErrorAction SilentlyContinue
        }

        $ProfileList = Get-ChildItem Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | Where-Object { $_.Name -notlike "*_Classes" -and $_.PSChildName -notin ("S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-80-1511743022-2277352901-878227523-1247458543-3245048236") }
        $UserList = foreach ($UserKey in $ProfileList) {
            @{
                ProfileKey  = $UserKey | Where-Object { $_.name -like "*" + $UserKey.PSChildName + "*" }
                UserName    = try { ((([system.security.principal.securityidentIfier]$UserKey.PSChildName).Translate([System.Security.Principal.NTAccount])).ToString()).substring(3) } catch { continue };
                SID         = $UserKey.PSChildName
                ProfilePath = Get-ItemProperty $UserKey.PSPath | Select-Object -ExpandProperty ProfileImagePath
            }
            
        }
        foreach ($item in $UserList) {
            if ($item.UserName -like "$($Script:UserName)*") {
                #[array]$kiosk += $item
                $kiosk = $item
            }
        }
        if ($kiosk -ne $null) {
            $KioskDesktopPath = $kiosk.profilepath.tostring() + "\Desktop"
            $KioskOneDriveDesktopPath = $kiosk.profilepath.tostring() + "\$($OneDriveOrgName)\Desktop"
            if (Test-Path -Path $KioskDesktopPath) {
                $Desktop = $KioskDesktopPath
            }
            if (Test-Path -Path $KioskOneDriveDesktopPath) {
                $Desktop = $KioskOneDriveDesktopPath
            }
        }
        $ExistingShortcuts_User = Get-ChildItem -Path $Desktop -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "*_$($Tag).lnk" }
        if ($ExistingShortcuts_User) {
            $ExistingShortcuts_User | Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        throw $_
    }
}

try {
    $Script:WinLogonKey = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    $RebootWhenComplete = $false
    $IsOOBEComplete =$false
        
    #region OOBE
    do {
        #if the script starts when OOBE is running, we should reboot after setting autologon.
        $defaultUserProcesses = (Get-Process -IncludeUserName | Where-Object { $_.UserName -like "*defaultUser0*" }).Count
        if ($defaultUserProcesses -gt 0) {
            $RebootWhenComplete = $true
        }
       
        $IsOOBEComplete = (($defaultUserProcesses -eq 0) -and (-not (Get-Process -Name WWAHost -ErrorAction SilentlyContinue)) -and ((Get-Process -Name winlogon -ErrorAction SilentlyContinue)))
        if ($IsOOBEComplete -eq $false) {
            Write-Host "OOBE is running. Waiting for OOBE to complete. Sleeping 5 seconds."
            Start-Sleep -Seconds 5
        }
    } until ($IsOOBEComplete -eq $true)
    #endregion

    if ($Disable.IsPresent) {
        Write-Host "Disable Parameter passed. Disabling Autologon configuration."
        Disable-AutoLogon
        Remove-AutorunKeys
        Remove-Shortcut
        #Write-Host "Attempting to remove scheduled task if exists"
        #Get-ScheduledTask -TaskName "Set-Autologon" -ErrorAction SilentlyContinue | Disable-ScheduledTask -ErrorAction SilentlyContinue
    }
    else {
        #test for internet connectivity
        $Connected = $false
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $timeSpan = New-TimeSpan -Minutes 2
        Write-Host "Testing internet connectivity." -ForegroundColor Yellow
        do {
            try {
                $result = Get-NetTCPConnection -State established -AppliedSetting Internet -remoteport 443 -ErrorAction SilentlyContinue | Where-Object RemoteAddress -NotLike '10.*' 
            }
            catch {}
            if ($result) {
                $Connected = $true
            }
            else {
                start-sleep -Seconds 2
            }
        } until ($Connected -or ($sw.ElapsedMilliseconds -ge $timeSpan.TotalMilliseconds))
    
        if ($Connected) {
            $EntraDeviceCert = Get-EntraDeviceCert
            $IntuneDeviceCert = Get-IntuneDeviceCert

            if ($IntuneDeviceCert -and $EntraDeviceCert) {
                Write-Host "Calling Azure Function getClientCreds"
                $ClientCredsParams = @{
                    URI             = "$($Uri)/api/GetManagedUser"
                    Headers         = @{
                        EntraDeviceCert  = [System.Convert]::ToBase64String($EntraDeviceCert.GetRawCertData())
                        IntuneDeviceCert = [System.Convert]::ToBase64String($IntuneDeviceCert.GetRawCertData())
                    }
                    UseBasicParsing = $true
                }
                    
                $GetClientCredsResult = Invoke-RestMethod @ClientCredsParams
                $ClientCreds = $GetClientCredsResult

                if (($ClientCreds.Name -eq $null) -or ($ClientCreds.Secret -eq $null )) {
                    Write-Host "Username not found in vault"
                }
                else {
                    $Script:UserPrincipalName = $ClientCreds.Name
                    $Script:UserName = $UserPrincipalName.Split('@')[0]

                    $Password = ConvertTo-SecureString $ClientCreds.Secret -AsPlainText -Force
                    $UserCreds = New-Object System.Management.Automation.PSCredential ("$($UserPrincipalName)", $Password)
                    $EntraUserCreds = New-Object System.Management.Automation.PSCredential ("AzureAD\$($UserPrincipalName)", $Password)
                    
                    if ($UserCreds) {
                        Write-Host "Created Usercreds"

                        #Run process with creds to cache the creds. This addresses network timing issues for startup.
                        #https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon#autoadminlogon-and-microsoft-entra-joined-only-computers
                        #In some cases the username will need to be prefixed with "AzureAD\"
                        if ($EntraUserCreds) {
                            try {
                                Start-Process cmd.exe -ArgumentList /c -Credential $EntraUserCreds -ErrorAction SilentlyContinue
                            }
                            catch {
                                $_
                                Write-Host "Failed to start process with Entra creds."
                            }
                        }

                        Set-AutoLogon -Credential $UserCreds
                        if ($UserPrincipalName) {
                            Get-Item -Path registry::$WinLogonKey
                            $ConfiguredUserName = Get-ItemPropertyValue -Path registry::$WinLogonKey -Name "DefaultUserName" -ErrorAction SilentlyContinue 
                            $ConfiguredAutLogon = (Get-ItemPropertyValue -Path registry::$WinLogonKey -Name "AutoAdminLogon" -ErrorAction SilentlyContinue)
                            if ($ConfiguredUserName -eq $UserPrincipalName -and $ConfiguredAutLogon -eq 1) {
                                Write-Host "AutoLogon Configured successfully for user $($UserPrincipalName)."
                            }
                        }
                        else {
                            Write-Error "Failed to configure autologon."
                        }
                    }
                    else {
                        Write-Host "No User Creds found - Removing Autologon"
                        Disable-AutoLogon
                    }
                }
                #endregion
            
                #region User Config
                if ($ClientCreds.Data) {
                    $CommandLines = foreach ($row in $ClientCreds.Data) {
                        if ($row.commandline.tostring() -like "*msedge*") {
                            $ShortcutName = $row.Arguments.tostring().split(".").replace("http://", "").replace("https://", "")[0]
                        }
                        else { 
                            $ShortcutName = $row.CommandLine.tostring().substring($row.CommandLine.tostring().lastindexof("\") + 1).replace(".exe", "")
                        }

                        Write-Host "Creating Shortcut for" $ShortcutName.replace("_$($Tag)", "")
                        New-Shortcut -Name $ShortcutName -CommandLine $row.CommandLine -Arguments $row.Arguments -UserName $UserName
                        if ($row.Arguments) {
                            "{0} {1}" -f $row.CommandLine, $row.Arguments    
                        }
                        else {
                            $row.CommandLine
                        }
                    }
                    Set-AutorunRegKeys -CommandLines $CommandLines -UserName $UserName
                }
                else {
                    Write-Host "No autorun keys found. Removing."
                    Remove-AutorunKeys
                    Remove-Shortcut
                }
            }
            else {
                Write-Warning "No valid Intune of Entra device certs found"
            }
        }
        else {
            Write-Warning "No internet connection found. Exiting."
        }
    }

}
catch {
    throw $_
}
finally {

    if ($RebootWhenComplete) {
        #Restart-Computer -Force
        Write-Host "Finished. Rebooting."
    }
    else {
        Write-Host "Finished."
    }
    Stop-Transcript -ErrorAction SilentlyContinue
}