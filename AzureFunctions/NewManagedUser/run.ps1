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
$licenseGroupId = $env:LicenseGroupId
$UPNPrefix = $env:UPNPrefix
$groupTag = $env:GroupTag
$displayname = $request.Query.UserName

#Serial number of the Intune/Autopilot device the user is being assigned to
$deviceSerialNumber = $request.Query.DeviceSerialNumber

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

# The following function validates that the API is presented with a known valid device cert thumbprint.
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
    if ([string]::IsNullOrEmpty($deviceSerialNumber) -and [string]::IsNullOrEmpty($displayname)) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - DeviceSerialNumber or UserName required."
        exit
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
    
    #Region UserName
    if (-not $displayname) {
        if ($skipAutopilotAssignment -eq $true) {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - UserName is required when SkipAutopilotAssignment is specified."
            exit
        }
        elseif ($UPNPrefix) {
            $displayname = "$($UPNPrefix)-$($deviceSerialNumber.Replace('-',''))"
            $userPrincipalName = "$($displayname)@$($domainName)"
        }
        else {
            $displayname = "$($deviceSerialNumber.Replace('-',''))"
            $userPrincipalName = "$($displayname)@$($domainName)"
        }
    }
    else {
        $userPrincipalName = "$($displayname)@$($domainName)"
    }
    
    if ($displayname -notmatch "^[a-zA-Z0-9\-]*$") {
        $status = [HttpStatusCode]::BadRequest
        $result += "DisplayName: $displayname should be AlphaNumeric please try again"
        exit
    }
    #endregion
    
    Write-Output "UserPrincipalName: $userPrincipalName"
    Write-Output "DisplayName: $displayname"
    Write-Output "DeviceSerialNumber: $deviceSerialNumber"

    # Create the user (replace 'userpurpose' with the actual attribute you want to set)
    $userBaseUrl = "https://graph.microsoft.com/beta/users"
    $userUrl = "users/$($userPrincipalName)"
    try {
        $CurrentUser = Get-GraphData -Query $userUrl -ErrorAction SilentlyContinue
        Write-Output "Current User: $($CurrentUser.id)"
    }
    catch {

    }

    #region Get KeyVault Access Token
    $resourceURI = "https://vault.azure.net"
    $tokenAuthURI = "$($Env:MSI_ENDPOINT)?resource=$($resourceURI)&api-version=2017-09-01"
    $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret" = $Env:MSI_SECRET } -Uri $tokenAuthURI -ErrorAction Stop
    $KVAZaccessToken = $tokenResponse.access_token
    #endregion

    if ($CurrentUser -eq $null) {
        Write-Output "Creating user..."

        $userPassword = Get-RandomPassword -Length 15

        $userBody = @{
            accountEnabled    = $true
            displayName       = $displayname
            mailNickname      = $displayname
            userPrincipalName = $userPrincipalName
            passwordProfile   = @{
                password                      = $userPassword
                forceChangePasswordNextSignIn = $false  # Disable password change at next sign-in
            }
        } | ConvertTo-Json

        # Invoke the REST method to create the user
        $CurrentUser = Invoke-RestMethod -Method POST -Uri $userBaseUrl -Headers $GraphHeaders -Body $userBody -ErrorAction Stop
        if ($CurrentUser) {
            #region Add Secret to Key Vault
            $azVaultParams = @{
                uri     = "https://$vaultName.vault.azure.net/secrets/$($displayname)?api-version=7.4"
                headers = @{
                    "Authorization" = "Bearer $($KVAZaccessToken)"
                    "Content-Type"  = "application/json"
                }
                body    = @{"value" = $userPassword } | ConvertTo-Json
                method  = "Put"
            }

            try {
                $azVaultParams
                Write-Output "About to set secret for $UserPrincipalName in vault."
                $KVout = Invoke-RestMethod @azVaultParams
                $SecretBody = @{
                    Name   = $userPrincipalName
                    Secret = $userPassword
                    Data   = $null
                }
            }
            catch {
                $_
                $status = [HttpStatusCode]::BadRequest
                $result += "Error - Something went wrong trying to set secret for $UserPrincipalName in vault. $($_.Exception.Message)"
                exit
            }

            Write-Output "KeyVault Entry created: $($KVout.id)"
            #endRegion

            #Region Check for User's Intune license
            Write-Output "User created: $($CurrentUser.id)"
            Start-Sleep -Seconds 10
            $LicUserParams = @{
                URI         = "https://graph.microsoft.com/beta/groups/$($LicenseGroupId)/members/`$ref"
                Body        = @{"@odata.id" = "https://graph.microsoft.com/beta/directoryObjects/$($CurrentUser.id)" } | ConvertTo-Json
                Headers     = $GraphHeaders
                ContentType = "application/json"
                Method      = "Post"
            }
            try {
                $LicOutput = Invoke-RestMethod @LicUserParams
                Start-Sleep -Seconds 10
            }
            catch {
                Write-Output "Error while attempting to assign user to license group."            
            }

            try {
                $LicUserParams.Body = $null
                $LicUserParams.Method = "Post"
                $LicUserParams.URI = "https://graph.microsoft.com/beta/users/$($CurrentUser.id)/reprocessLicenseAssignment"
                $syncLicRes = Invoke-RestMethod @LicUserParams
        
                $LicUserParams.Method = "Get"
                $LicUserParams.URI = "https://graph.microsoft.com/v1.0/users/$($CurrentUser.id)/licenseDetails"
                $LicUserParams.ErrorAction = "Stop"
                $userLicRes = Invoke-RestMethod @LicUserParams
                Invoke-RestMethod @LicUserParams
            }
            catch {
                $_
                Write-Output "Error while attempting to reprocess licenses."
            }
        }
        else {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - User not created."
            exit
        }
    }
    else {
        $UserName = $UserPrincipalName.Split('@')[0]
        $azVaultParams = @{
            Uri     = "https://$($vaultName).vault.azure.net/secrets/$($UserName)`?api-version=7.4"
            Headers = @{
                "Authorization" = "Bearer $KVAZaccessToken"
                "Content-Type"  = "application/json"
            }
        }

        try {
            Write-Output "Getting secret for $UserPrincipalName from vault."
            $SecretObject = Invoke-RestMethod @azVaultParams -ErrorAction Stop
            $SecretBody = @{
                Name   = $userPrincipalName
                Secret = $SecretObject.value
                Data   = $null
            }
            if (-not $SecretObject) {
                $status = [HttpStatusCode]::NotFound
                $result += "Error - No user password found in for user $UserPrincipalName."
                exit
            }
        }
        catch {
            $_
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Something went wrong trying to get secret for $UserPrincipalName from vault."
            exit
        }
    }

    if (-not $CurrentUser) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - User not created."
        exit
    }
    #end Region

    if ($SecretBody) {
        $status = [HttpStatusCode]::OK
        $result += $SecretBody
    }
    else {
        $status = [HttpStatusCode]::OK
        $result = "User already existed."
    }
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
