<#
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement
#>

using namespace System.Net

# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
$result = @()
$status = [HttpStatusCode]::Unauthorized
#$Debug = $True

$vaultName = $env:VaultName
$domainName = $env:DomainName
$groupTag = $env:GroupTag
$vaultName = $env:VaultName
$domainName = $env:DomainName
$UPNPrefix = $env:UPNPrefix

#UserPrincipalName of the user to be assigned to the Autopilot device
$userPrincipalName = $request.Query.UserPrincipalName

#Serial number of the Intune/Autopilot device the user is being assigned to
$deviceSerialNumber = $request.Query.DeviceSerialNumber

#Create the user but don't assign to an Autopilot device
$skipAutopilotAssignment = $request.Query.SkipAutopilotAssignment

#Create the user but don't assign to an Intune device
$skipIntuneAssignment = $request.Query.SkipIntuneAssignment

function Get-GraphData {
    [cmdletbinding()]
    param (
        $ver = "beta",
        $query
    )

    try { 
        $RequestParams = @{
            Uri     = "https://graph.microsoft.com/$($ver)/$($query)"
            Method  = "Get"
            Headers = $Script:GraphHeaders
        }
        $Response = Invoke-RestMethod @RequestParams -ErrorAction Stop
        if ($Response.value) {
            $result += $Response.value
            while ($Response.'@odata.nextLink') {
                $RequestParams = @{
                    URI    = $Response.'@odata.nextLink'
                    Method = "Get"
                }
                $Response = Invoke-RestMethod @RequestParams -ErrorAction Stop
                $result += $Response.value
                $Response = $null
            }
            return $result
        }
        else {
            #single result returned. handle it.
            return $Response
        }
    }
    catch {
        $_.exception
        throw $_
    }
}

# The following function validates that the API is presented with a known valid device thumbprint.
# For the use case of a kiosk workstation, this is an acceptable additional risk.
# For different use cases alternative authentication should be used (e.g., Intune Cert Profile or Azure Managed Identity)
function Confirm-ClientCertAuth {
    [cmdletbinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$EntraDeviceCert = $script:EntraDeviceCert,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IntuneDeviceCert = $script:IntuneDeviceCert
    )
    try {
        $ValidIntuneDevice = $false
        $ValidEntraDevice = $false
        $ValidEntraDeviceThumbprint = $false
        
        $Script:EntraDeviceId = $EntraDeviceCert.Subject.Replace("CN=", "")
        $Script:IntuneDeviceId = $IntuneDeviceCert.Subject.Replace("CN=", "")

        if ($EntraDeviceId) {
            $EntraDeviceQuery = "devices(deviceId='$($EntraDeviceId)')?`$select=id,displayName,alternativeSecurityIds"
            $EntraDevice = Get-GraphData -Query $EntraDeviceQuery
            
            if ($EntraDevice) {
                $ValidEntraDevice = $true
                if ($EntraDevice.alternativeSecurityIds) {
                    [byte[]]$SecIdSecIdBytes = [Convert]::FromBase64String($EntraDevice.alternativeSecurityIds.key)
                    $encoding = New-Object System.Text.UnicodeEncoding
                    $DecodedID = $encoding.GetString($SecIdSecIdBytes)
                    if ($DecodedID -like "*$($EntraDeviceCert.Thumbprint)*") {
                        $ValidEntraDeviceThumbprint = $true
                    }
                    else {
                        $status = [HttpStatusCode]::Unauthorized
                        $result += "Invalid Entra Thumbprint"
                    }
                }
            }
            else {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid Entra Device"
            }
        }

        if ($IntuneDeviceID) {
            $IntuneDeviceQuery = "deviceManagement/ManagedDevices/$($IntuneDeviceID)"
            $IntuneDevice = Get-GraphData -Query $IntuneDeviceQuery
            if ($IntuneDevice) {
                $ValidIntuneDevice = $true
            }
            else {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid Intune Device"
            }
        }

        if ($ValidIntuneDevice -and $ValidEntraDevice -and $ValidEntraDeviceThumbprint) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        throw $_
    }
}

function Get-RandomPassword {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(4, [int]::MaxValue)]
        [int] $length,
        [int] $upper = 1,
        [int] $lower = 1,
        [int] $numeric = 1,
        [int] $special = 1
    )

    if ($upper + $lower + $numeric + $special -gt $length) {
        throw "Number of upper/lower/numeric/special characters must be lower or equal to the total length."
    }

    $uCharSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lCharSet = "abcdefghijklmnopqrstuvwxyz"
    $nCharSet = "0123456789"
    $sCharSet = "/\*-+,!?= ()@;:._"

    $charSet = ""

    if ($upper -gt 0) { $charSet += $uCharSet }
    if ($lower -gt 0) { $charSet += $lCharSet }
    if ($numeric -gt 0) { $charSet += $nCharSet }
    if ($special -gt 0) { $charSet += $sCharSet }

    $charSet = $charSet.ToCharArray()
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] ($length)
    $rng.GetBytes($bytes)
    $result = New-Object char[] ($length)

    for ($i = 0; $i -lt $length; $i++) {
        $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
    }

    return (-join $result)
}

try {

    if ($deviceSerialNumber -eq $null -or $deviceSerialNumber -eq "" -and $skipAutopilotAssignment -ne $true -and $SkipIntuneAssignment -ne $true) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - DeviceSerialNumber is required."
        exit
    }
    else {
        if (-not $userPrincipalName) {
            if ($UPNPrefix) {
                $displayname = "$($UPNPrefix)-$($deviceSerialNumber.Replace('-',''))"
                $userPrincipalName = "$($displayname)@$($domainName)"
            }
            else {
                $displayname = "$($deviceSerialNumber.Replace('-',''))"
                $userPrincipalName = "$($displayname)@$($domainName)"
            }
        }
    }

    #region HeaderCerts
    
    if ($Request.Headers."EntraDeviceCert") {
        try {
            $script:EntraDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers."EntraDeviceCert"))
            if ((-not $EntraDeviceCert)) {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid or Missing Entra Device Cert in Header."
                Exit
            }
        }
        catch {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - EntraDeviceCert format is invalid."
            exit
        }
    
        if ($Request.Headers."IntuneDeviceCert") {
            try {
                $script:IntuneDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers."IntuneDeviceCert"))
                if ((-not $IntuneDeviceCert)) {
                    $status = [HttpStatusCode]::Unauthorized
                    $result += "Error - Missing Intune Device Cert in Header."
                    Exit
                }
            }
            catch {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - IntuneDeviceCert format is invalid."
                exit
            }
        }
    }
        
    #endregion

    #region Get Graph AccessToken with Managed System Identity
    $BaseURI = 'https://graph.microsoft.com/'
    $tokenParams = @{
        Uri     = "${Env:MSI_ENDPOINT}?resource=${BaseURI}&api-version=2017-09-01"
        Method  = "Get"
        Headers = @{ Secret = $Env:MSI_SECRET }
    }
    $Response = Invoke-RestMethod @tokenParams
    $Token = $Response.access_token
    $Script:GraphHeaders = @{
        "Authorization"    = "Bearer $token"
        "Content-Type"     = "application/json"
        "ConsistencyLevel" = "Eventual"
    }
    #endregion
    if ($Debug -ne $True) {
        if (-not (Confirm-ClientCertAuth)) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Device Cert Validation Failed."
            exit
        }
    }
    
    Write-Output "UserPrincipalName: $userPrincipalName"
    Write-Output "DeviceSerialNumber: $deviceSerialNumber"

    #region Check AutoPilotDevice
    if ($skipAutopilotAssignment -ne $true) {
        Write-Output "Checking AutoPilot Device"
        $APDeviceURL = "deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'$($deviceSerialNumber)')"
        $APDevice = Get-GraphData -Query $APDeviceURL
        if (-not $APDevice -or ($APDevice.serialNumber -ne $deviceSerialNumber)) {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - AutoPilot Device not found."
            exit
        }
        Write-Output "AutoPilot Device: $($APDevice.id)"
    }

    #region Check AutoPilotDevice
    if ($skipIntuneAssignment -ne $true) {
        Write-Output "Checking Intune Device"
        $IntuneDeviceURL = "deviceManagement/managedDevices?`$filter=contains(serialNumber,'$($deviceSerialNumber)')"
        $IntuneDevice = Get-GraphData -Query $IntuneDeviceURL
        if (-not $IntuneDevice -or ($IntuneDevice.serialNumber -ne $deviceSerialNumber)) {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Intune Device not found."
            exit
        }
        Write-Output "Intune Device: $($IntuneDevice.id)"
    }

    # Get the user
    if ($UserPrincipalName) {
        Write-Host "Getting User: $($UserPrincipalName)"
        $userBaseUrl = "https://graph.microsoft.com/beta/users"
        $userUrl = "users/$($userPrincipalName)"
        try {
            $CurrentUser = Get-GraphData -Query $userUrl -ErrorAction SilentlyContinue
            Write-Output "Current User: $($CurrentUser.id)"
        }
        catch {

        }
    }

    if ($CurrentUser -eq $null) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - User $UserPrincipalName not found. Exiting."
        exit
    }

    $HasIntuneLicense = $false
    if ($CurrentUser) {
        Write-Output "Checking User Intune License"
        $UserStatusParams = @{
            URI         = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppStatuses('userstatus')?userId=$($CurrentUser.id)"
            Headers     = $GraphHeaders
            ContentType = "application/json"
            Method      = "Get"
            ErrorAction = "Stop"
        }
        $UserStatusParams.URI
        $UserStatusResponse
        $UserStatusResponse = Invoke-RestMethod @UserStatusParams
        if ($UserStatusResponse.content) {
            $ValidationStatuses = $UserStatusResponse.content.validationStatuses
            $IntuneLicenseStatus = $ValidationStatuses | Where-Object { $_.validationName -eq 'Intune License' }
            if ($IntuneLicenseStatus.State -eq 'Pass') {
                $HasIntuneLicense = $True
                Write-Output "User has an Intune license."
            }
            else {
                $_
                $status = [HttpStatusCode]::BadRequest
                $result += "Error - No Intune license found for $UserPrincipalName. Exiting."
                exit
            }
        }
        else {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Unknown error retrieving managedAppStatuses. Exiting."
            exit
        }
    }
    else {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - User $UserPrincipalName not found. Create user before proceeding. Exiting."
        exit
    }

    if ($skipAutopilotAssignment -ne $true) {
        Write-Output "Creating Autopilot User Assignment"
        $APParams = @{
            Uri     = "https://graph.microsoft.com/beta/deviceManagement/windowsAutopilotDeviceIdentities/$($APDevice.id)/UpdateDeviceProperties"
            Body    = @{
                userPrincipalName   = $CurrentUser.userPrincipalName
                addressableUserName = $CurrentUser.displayname
                groupTag            = $groupTag
            } | ConvertTo-Json
            Method  = "Post"
            Headers = $GraphHeaders
        }

        $APParams.Uri
        $APParams.Body

        Write-Output "Assigning Autopilot User $($userPrincipalName)"
        try {
            $APAssignRes = Invoke-RestMethod @APParams
        }
        catch {
            $_
            $_.Exception.Message
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Failed to set Autopilot assignment. Exiting."
            exit
        }
    }

    if ($skipIntuneAssignment -ne $true) {
        Write-Output "Creating Intune User Assignment"
        $IntuneParams = @{
            URI     = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/$($IntuneDevice.id)/users/`$ref"
            Body    = @{
                "@odata.id" = "https://graph.microsoft.com/beta/users/$($CurrentUser.id)"
            } | ConvertTo-Json
            Method  = "Post"
            Headers = $GraphHeaders
        }

        Write-Output "Assigning Intune User $($userPrincipalName)"
        try {
            $IntuneAssignRes = Invoke-RestMethod @IntuneParams
        }
        catch {
            $_.Exception.Message
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Failed to set Intune assignment. Exiting."
            exit
        }
    }

    $status = [HttpStatusCode]::OK
    $result = "Successfully Created Autopilot/Intune user assignment."
}
catch {
    $status = [HttpStatusCode]::BadRequest
    $result += @{Exception = $_.Exception.Message; StackTrace = $_.ScriptStackTrace }
}
finally {
    Push-OutputBinding -Name Response -Clobber -Value ([HttpResponseContext]@{
            StatusCode = $status
            Body       = $result | ConvertTo-Json -Depth 10
        })
}

