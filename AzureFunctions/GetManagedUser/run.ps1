<#
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement
#>
using namespace System.Net

param($Request, $TriggerMetadata)
$result = @()
$status = [HttpStatusCode]::Unauthorized
$vaultName = $env:vaultName
#$Debug = $True

if ($Debug) {
    $IntuneDeviceId = $Request.Query.IntuneDeviceId
    $EntraDeviceId = $Request.Query.EntraDeviceId
}

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

try {

    #region HeaderCerts
    if ($Request.Headers.EntraDeviceCert) {
        try {
            $script:EntraDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers.EntraDeviceCert))
            if ((-not $EntraDeviceCert)) {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Invalid or Missing Entra Device Cert in Header."
                exit
            }
        }
        catch {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - EntraDeviceCert format is invalid."
            exit
        }
    }
    else {
        if ($Debug -ne $True) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Invalid or Missing Entra Device Cert in Header."
            exit
        }
    }
    if ($Request.Headers.IntuneDeviceCert) {
        try {
            $script:IntuneDeviceCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]([Convert]::FromBase64String($Request.Headers."IntuneDeviceCert"))
            if ((-not $IntuneDeviceCert)) {
                $status = [HttpStatusCode]::Unauthorized
                $result += "Error - Missing Intune Device Cert in Header."
                exit
            }
        }
        catch {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - IntuneDeviceCert format is invalid."
            exit
        }
    }
    else {
        if ($Debug -ne $True) {
            $status = [HttpStatusCode]::Unauthorized
            $result += "Error - Missing Intune Device Cert in Header."
            exit
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


    $APDeviceURL = "deviceManagement/windowsAutopilotDeviceIdentities?`$filter=azureActiveDirectoryDeviceId+eq+'$($EntraDeviceID)'"
    $APDevice = Get-GraphData -Query $APDeviceURL
    
    $IntunePrimaryUserQuery = "deviceManagement/managedDevices/$($IntuneDeviceId)/users?`$select=id,userPrincipalName"
    $UserObj = Get-GraphData -Query $IntunePrimaryUserQuery
    if ($UserObj.userPrincipalName) {
        Write-Output "Intune Device Id: $($IntuneDeviceId)"
        $UserPrincipalName = $UserObj.userPrincipalName
        Write-Output "Found User $UserPrincipalName assigned to Intune device $IntuneDeviceId"
    }
    else {
        if (-not $APDevice) {
            $status = [HttpStatusCode]::NotFound
            $result += "Error - Intune and AutoPilot Device not found."
        }
        $UserPrincipalName = $APDevice.userPrincipalName
        if($UserPrincipalName) {
            Write-Output "Found User $UserPrincipalName assigned to Autopilot device SerialNumber: $($APDevice.serialNumber)"
        }
        else {
            $status = [HttpStatusCode]::NotFound
            $result += "Error - AutoPilot assigned user not found."
        }
    }
    
    #endregion

    #region get autorun entries
    if ($UserPrincipalName) {
        $resourceURI = "https://vault.azure.net"
        $tokenAuthURI = "${Env:MSI_ENDPOINT}?resource=$resourceURI&api-version=2017-09-01"
        $tokenParams.Uri = $tokenAuthURI
        $tokenResponse = Invoke-RestMethod @tokenParams
        $KVAZaccessToken = $tokenResponse.access_token

        $UserName = $UserPrincipalName.Split('@')[0]
        
        $azVaultParams = @{
            Uri     = "https://$($vaultName).vault.azure.net/secrets/$($UserName)`?api-version=7.4"
            Headers = @{
                "Authorization" = "Bearer $KVAZaccessToken"
                "Content-Type"  = "application/json"
            }
        }

        try {
            $SecretObject = Invoke-RestMethod @azVaultParams -ErrorAction Stop
            if (-not $SecretObject) {
                $status = [HttpStatusCode]::NotFound
                $result += "Error - No user password found in for user $UserPrincipalName."
                exit
            }
        
        }
        catch {
            $status = [HttpStatusCode]::BadRequest
            $result += "Error - Something went wrong trying to get secret for $UserPrincipalName from vault."
            exit
        }
        #endregion

        #get kiosk autorun command lines from storage account
        #https://github.com/tabs-not-spaces/CodeDump/tree/master/AzTableAPIExamples
        #Thanks Ben!
        $storageAccountName = $env:StorageAccountName
        $tableName = $env:TableName
        $storageAccountkey = $env:StorageAccountKey
        $columnName = 'UserName'
        $columnValue = $userPrincipalName

        $BaseURI = 'https://storage.azure.com/'
        $azStorageTokenParams = @{
            Uri     = "${Env:MSI_ENDPOINT}?resource=${BaseURI}&api-version=2017-09-01"
            Method  = "Get"
            Headers = @{ Secret = $Env:MSI_SECRET }
        }
        $Response = Invoke-RestMethod @azStorageTokenParams
        $azStorageToken = $Response.access_token
      
        $azTableParams = @{
            Uri         = "https://$($storageAccountName).table.core.windows.net/$($tableName)?`$filter=($ColumnName eq '$ColumnValue')"
            Method      = "GET"
            ContentType = "application/json"
            Headers     = @{    
                Authorization  = "Bearer $azStorageToken"
                Accept         = "application/json;odata=fullmetadata"
                'x-ms-date'    = (Get-Date).ToUniversalTime().toString('R')
                "x-ms-version" = "2020-04-08"
            }
        }
      
        $rows = Invoke-RestMethod @azTableParams -ErrorAction SilentlyContinue
    }
    else {
        $status = [HttpStatusCode]::NotFound
        $result += "Error - No User Assigned to Intune or Autopilot device."
        exit
    }
    #endregion
    
    $SecretBody = @{
        Name   = $userPrincipalName
        Secret = $SecretObject.value
        Data   = $rows.value
    }
    
    $status = [HttpStatusCode]::OK
    $result += $SecretBody

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
