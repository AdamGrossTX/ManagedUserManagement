[]: # (FILEPATH: /d:/Github/ManagedUserManagement/README.md)

# ManagedUserManagement

Solution to manage kiosk user accounts and configure autologon

## Instructions

1. Change function app settings for all function apps:
    - Settings > Configuration > General Settings > Platform Settings > Platform = 64 Bit
    - Settings > Configuration > General Settings > HTTP Version = 2.0
    - Functions > App Files > profile.ps1 = Comment out all lines.

2. In the Admin function app, create a new function called "NewManagedUser" and add the code from `NewManagedUser\run.ps1`:
    - Function Template = Trigger
    - Authorization Level = Anonymous
    - Function name = NewManagedUser

3. In the Admin function app, create a new function called "AssignManagedUser" and add the code from `AssignManagedUser\run.ps1`:
    - Function Template = Trigger
    - Authorization Level = Anonymous
    - Function name = AssignManagedUser

4. In the Admin function app, create a new function called "ManageManagedUser" and add the code from `ManageManagedUser\run.ps1`:
    - Function Template = Trigger
    - Authorization Level = Anonymous
    - Function name = ManageManagedUser

5. In the Client function app, create a new function called "GetManagedUser" and add the code from `GetManagedUser\run.ps1`:
    - Function Template = Trigger
    - Authorization Level = Anonymous
    - Function name = GetManagedUser

6. API > CORS > Allowed Origins = https://portal.azure.com

7. Update `ClientScripts\Set-AutoLogon $PwdURI` to the URI of the GetManagedUser function.

8. After creating a new account, run the following code to create the autolaunch entry/entries for the account:
    ```powershell
    $TableRow = @{
         UserName = "KSK-42867596804229277229006352@asquaredozenlab.com"
         CommandLine = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
         Arguments = "https://asquaredozen.com"
    }
    Add-AzTableRow -Table $StorageTable.CloudTable -PartitionKey 1 -RowKey (New-Guid).Guid -Property $TableRow
    ```



## Sample Command lines
```powershell
        .\AdminScripts\Build-AzureResources.ps1 -objectRootName "ManagedUserDemo1" -DomainName "asquaredozenlab.com" -LicenseGroupName "License" -GroupTag "Kiosk" -UPNPrefix "KSK"
        
        .\AdminScripts\CreateAndAssignUsers.ps1 -FunctionAppURI "https://faasdmanageduserdemo1admin.azurewebsites.net" -DeviceSerialNumbers @('ABCD1245''FEWE2343') -SkipIntuneAssignment
        
        .\Build-ClientInstallApp.ps1 -SourcePath = ".\ClientScripts" -SetupFile = "install.ps1" -OutputFolder = ".\Win32"
        
        #Intune Win32 App Command Line
        %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -File "install.ps1" -Uri "https://faasdmanageduserdemo1client.azurewebsites.net"
        
        .\ClientScripts\Set-AutoLogon.ps1 -Uri "https://faasdmanageduserdemo1client.azurewebsites.net" -tag 'KSK' -OneDriveOrgName "OneDrive - A Square Dozen Lab"
```