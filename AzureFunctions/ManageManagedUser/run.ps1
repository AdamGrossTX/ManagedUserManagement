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

$UserPrincipalName = $request.Query.UserPrincipalName
$Password = $request.Query.Password
$ResetPassword = $request.Query.ResetPassword

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
    
    if (-not $UserPrincipalName) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - UserName is required."
        exit
    }
    
    if (([string]::IsNullOrEmpty($Password)) -and ($ResetPassword -ne $True)) {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - Password or ResetPassword are required."
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
    
    #endregion
    
    Write-Output "UserPrincipalName: $userPrincipalName"

    # Create the user (replace 'userpurpose' with the actual attribute you want to set)
    $userBaseUrl = "https://graph.microsoft.com/beta/users"
    $userUrl = "users/$($userPrincipalName)"
    try {
        $CurrentUser = Get-GraphData -Query $userUrl -ErrorAction SilentlyContinue
        Write-Output "Current User: $($CurrentUser.id)"
        if ($CurrentUser -eq $null) {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - User not found in Azure."
            exit
        }
    }
    catch {
        $status = [HttpStatusCode]::BadRequest
        $result += "Error - User not found in Azure."
        exit
    }


    #region Get KeyVault Access Token
    $resourceURI = "https://vault.azure.net"
    $tokenAuthURI = "$($Env:MSI_ENDPOINT)?resource=$($resourceURI)&api-version=2017-09-01"
    $tokenResponse = Invoke-RestMethod -Method Get -Headers @{"Secret" = $Env:MSI_SECRET } -Uri $tokenAuthURI -ErrorAction Stop
    $KVAZaccessToken = $tokenResponse.access_token
    #endregion

    Write-Output "Creating user..."

    if ($ResetPassword) {
        if ($Password) {
            $userPassword = $Password
        }
        else {
            Write-Output "Resetting password for $UserPrincipalName."
            $userPassword = Get-RandomPassword -Length 15
        }
    }

    $UserParams = @{
        Uri     = "$($userBaseUrl)/$($CurrentUser.id)"
        Headers = $GraphHeaders
        Body    = @{
            passwordProfile = @{
                password                      = $userPassword
                forceChangePasswordNextSignIn = $false  # Disable password change at next sign-in
            }
        } | ConvertTo-Json
        Method  = "Patch"
        #ErrorAction = "Stop"
    }
    $Result = Invoke-RestMethod @UserParams

    
    if ($CurrentUser) {
        #region Add Secret to Key Vault
        $azVaultParams = @{
            uri     = "https://$vaultName.vault.azure.net/secrets/$($CurrentUser.displayName)?api-version=7.4"
            headers = @{
                "Authorization" = "Bearer $($KVAZaccessToken)"
                "Content-Type"  = "application/json"
            }
            body    = @{"value" = $userPassword } | ConvertTo-Json
            method  = "Put"
        }

        try {
            Write-Output "About to set secret for $UserPrincipalName in vault."
            $KVout = Invoke-RestMethod @azVaultParams
            $SecretBody = [pscustomobject]@{
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
    }
    
    if ($SecretBody) {
        $status = [HttpStatusCode]::OK
        $result = $SecretBody
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
