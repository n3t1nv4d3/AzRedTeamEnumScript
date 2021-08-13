# Azure AD RedTeam Enumeration Script
Azure AD RedTeam Full Enumeration Script used to query all aspects of your target Azure tenant, focusing on the Active Directory (AD) component using 4 common modules to interact with Azure AD via PowerShell. The script will save all output from each enumeration task into a folder separating out the output files into appropriate folders for analyze later. This script saved me a lot of time on the enumeration portion for the Pentester Academy CARTP exam. Will be extremely useful for any Azure AD pentesting engagement. The script contains more information within it to help you enumeration discovered resources further, so ensure you read the commented out portions! 

The following 4 modules are used:

* [AzureAD Module](https://docs.microsoft.com/en-us/powershell/module/azuread/?view=azureadps-2.0)
* [Az PowerShell Module](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-6.3.0)
* [Azure Command-Line Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/)
* [AAD Internals](https://o365blog.com/aadinternals/)

This script is also designed to run other popular scripts and modules intended to get the most information out of you target Azure AD tenant. You should look into their project to understand the full capabilities of the tools besides the small task performed within this script.

* [AzureHound](https://github.com/BloodHoundAD/AzureHound)
* [MicroBurst: A PowerShell Toolkit for Attacking Azure](https://github.com/NetSPI/MicroBurst)


All appropriate tokens are required as part of the script when needed.

## Installation and Usage

As an administrator install the following on your system to interact with Azure:

* [AzureAD Module](https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0) - ```(main) Install-module AzureAD OR (public) Install-module AzureADPreview```
* [Az PowerShell Module](https://docs.microsoft.com/en-us/powershell/azure/new-azureps-module-az?view=azps-6.3.0) - ```Install-Module Az -Force```
* [Azure Command-Line Interface (CLI)](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-powershell) - ```Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi```
* [AAD Internals](https://o365blog.com/aadinternals/#installation) - ```Install-Module AADInternals```

You can also edit the script to do all the above as well!

To run the script:

```.\AzRedTeamEnumScript.ps1```

![script](https://user-images.githubusercontent.com/20993128/129288516-892aa15c-fd19-48ef-81e4-2dc4a1743c5a.png)

# AzAD RedTeam User Enumeration Script
You can also use the `User` enumeration script when you find credentials to another user in the same domain and want to query for what that new user and/or service principal has access to and not have to run the full enumeration script again... Looking to update this to combine into one script and provide the option to choice which enumeration mode to run "Full" or "User". 

To run the script:

```.\AzureUserAccessEnumScript.ps1```

![script2](https://user-images.githubusercontent.com/20993128/129289022-46d24e03-8d5c-4f92-b08a-9121ded862f9.png)

## Author
- [@n3t1nv4d3](https://github.com/n3t1nv4d3) author and researcher.
