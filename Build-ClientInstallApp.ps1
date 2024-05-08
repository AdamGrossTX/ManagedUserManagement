<#
.SYNOPSIS
    Builds a client installation app using IntuneWinAppUtil.exe.

.DESCRIPTION
    This script builds a client installation app by using IntuneWinAppUtil.exe. It takes the source path of the client scripts, the setup file name, and the output folder as parameters. If the source path exists, it runs IntuneWinAppUtil.exe with the provided parameters to create the client installation app. If the source path does not exist, it displays an error message and exits.

.PARAMETER SourcePath
    The path to the directory containing the client scripts.

.PARAMETER SetupFile
    The name of the setup file to be included in the client installation app.

.PARAMETER OutputFolder
    The path to the output folder where the client installation app will be created.

.EXAMPLE
    Build-ClientInstallApp.ps1 -SourcePath ".\ClientScripts" -SetupFile "install.ps1" -OutputFolder ".\Win32"
    Builds a client installation app using the client scripts located in the ".\ClientScripts" directory, with the setup file named "install.ps1", and saves the output in the ".\Win32" folder.

.NOTES
    Author: Adam Gross - @AdamGrossTX
    GitHub: https://github.com/AdamGrossTX/ManagedUserManagement
#>

param (
    $SourcePath = ".\ClientScripts",
    $SetupFile = "install.ps1",
    $OutputFolder = ".\Win32"
)

if(Test-Path -Path $SourcePath) {
    .\IntuneWinAppUtil.exe -c $SourcePath -s $SetupFile -o $OutputFolder -q
}
else {
    Write-Host "Source Path not found" -ForegroundColor Red
    exit
}