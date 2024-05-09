# ManagedUserManagement

Solution to manage kiosk user accounts and configure autologon

## Background

There are many ways to manage Kiosks. This is just one option. The goal of this solution is to use an Entra user account as a kiosk account that automatically logs on and auto launches specified processes without ever needing the know the user's password.

This solitions will build an Azure Key Vault to store a kiosk user credential. The kiosk account can then be assigned to a device that's registered in Autopilot or in Intune. Once the user is assigned and password stored in the Key Vault, a local client script will run which will pull the user creds from the vault and configure autologon for the workstation. Once the device is rebooted, the device should automaticlly logon.

## Requirements

For this solution, you will need

- Azure Subscription
- Permissions to create
  - Azure Resource Group
  - Azure Storage Account
  - Azure Storage Table
  - Azure Function App
  - Azure Key Vault
  - Set permissions for Service Principal
- Intune licenses for user accounts

## Azure Resource Creation

This script will create Azure resources using the naming convention below. Edit `Build-AzureResources.ps1` to adjust the naming convention to meet your needs.

```powershell
<resourceTypePrefix><ObjectRootName>
rgManagedUserDemo1 - Resource Group
faManagedUserDemo1 - Function App
saManagedUserDemo1 - Storage Account
kvManagedUserDemo1 - Key Vault
```

1. To build all Azure resources required, run `Build-AzureResources.ps1`. Change the parameters to meet your needs.

  ```powershell
  .\AdminScripts\Build-AzureResources.ps1 -objectRootName "ManagedUser" -DomainName "asquaredozenlab.com" -LicenseGroupName "License" -GroupTag "Kiosk" -UPNPrefix "KSK"
  ```

2. Change function app settings for all function apps:

   - Settings > Configuration > General Settings > Platform Settings > Platform = **64 Bit**
   - Settings > Configuration > General Settings > HTTP Version = **2.0**
   - Functions > App Files > `profile.ps1` = Comment out all lines
   - API > CORS > Allowed Origins = `https://portal.azure.com`

3. In the Admin function app, create a new function called "NewManagedUser" and add the code from `NewManagedUser\run.ps1`:

   - Function Template = Trigger
   - Authorization Level = Anonymous
   - Function name = NewManagedUser

4. In the Admin function app, create a new function called "AssignManagedUser" and add the code from `AssignManagedUser\run.ps1`:

   - Function Template = Trigger
   - Authorization Level = Anonymous
   - Function name = AssignManagedUser

5. In the Admin function app, create a new function called "ManageManagedUser" and add the code from `ManageManagedUser\run.ps1`:

   - Function Template = Trigger
   - Authorization Level = Anonymous
   - Function name = ManageManagedUser

6. In the Client function app, create a new function called "GetManagedUser" and add the code from `GetManagedUser\run.ps1`:

   - Function Template = Trigger
   - Authorization Level = Anonymous
   - Function name = GetManagedUser

## AutoRun Configuration

After creating a new account, run the following code to create the autolaunch entry/entries for the account:

```powershell
$ResourceGroupName = "rgASDManagedUserDemo1"
$StorageTableName = "tblASDManagedUserDemo1"
$StorageAccountName = "saasdmanageduserdemo1"
Connect-AzAccount
$StorageAccount = Get-AzStorageAccount -Name $StorageAccountName -ResourceGroupName $ResourceGroupName
$StorageTable = Get-AzStorageTable -Name $StorageTableName -Context $StorageAccount.Context

$TableRow = @{
    UserName = "KSK-42867596804229277229006352@asquaredozenlab.com"
    CommandLine = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    Arguments = "https://asquaredozen.com"
}
Add-AzTableRow -Table $StorageTable.CloudTable -PartitionKey 1 -RowKey (New-Guid).Guid -Property $TableRow
```

For more information about Edge command line options: https://learn.microsoft.com/deployedge/microsoft-edge-configure-kiosk-mode[https://learn.microsoft.com/deployedge/microsoft-edge-configure-kiosk-mode](https://learn.microsoft.com/deployedge/microsoft-edge-configure-kiosk-mode)

## Client Script

The solution requires a client-side script that will run to configure autologon/autolaunch.

1. Create the intunewin file from the `ClientScripts` content

     ```powershell
     .\Build-ClientInstallApp.ps1 -SourcePath = ".\ClientScripts" -SetupFile = "install.ps1" -OutputFolder = ".\Win32"`
     ```

2. Get the Function App URL from the Client function App.
3. Create a new Intune Win32 App with this command line

    ```powershell
    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "install.ps1" -Uri "<CLIENT FUNCTION APP COMMAND LINE FROM STEP 2>"
    ```

## New Managed User

  ```powershell
  .\AdminScripts\NewManagedUser.ps1 -FunctionAppURI "https://<Admin function App URL>" -DeviceSerialNumbers @('ABCD1245''FEWE2343') 
  ```

## Assign Managed User

  ```powershell
  $UserToDeviceMap = @(
      [PSCustomObject]@{
          UserPrincipalName = "UPN"
          SerialNumber      = "SerialNumber"
      }
  )
  
  .\AdminScripts\AssignManagedUser.ps1 -FunctionAppURI "https://<Admin function App URL>" -UserToDeviceMap $UserToDeviceMap
  ```

## Manage Managed User

  ```powershell
  .\AdminScripts\ManageManagedUser.ps1 -FunctionAppURI "https://<Admin function App URL>" -UserPrincipalName "MyUPN" -Password "MyPassword"
  ```
