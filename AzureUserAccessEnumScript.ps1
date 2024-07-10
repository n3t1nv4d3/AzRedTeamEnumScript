#AzAD RedTeam User Enum Script
#created by n3t1nv4d3
#July 27, 2021


$logo=@"

 █████╗ ███████╗    ██████╗ ███████╗██████╗     ████████╗███████╗ █████╗ ███╗   ███╗
██╔══██╗╚══███╔╝    ██╔══██╗██╔════╝██╔══██╗    ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║
███████║  ███╔╝     ██████╔╝█████╗  ██║  ██║       ██║   █████╗  ███████║██╔████╔██║
██╔══██║ ███╔╝      ██╔══██╗██╔══╝  ██║  ██║       ██║   ██╔══╝  ██╔══██║██║╚██╔╝██║
██║  ██║███████╗    ██║  ██║███████╗██████╔╝       ██║   ███████╗██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝╚═════╝        ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝
                                                                                      
 Azure AD User Enumeration Script by @n3t1nv4d3
"@

Write-Host $logo -ForegroundColor Red
Write-Host
Write-Host "Read the script for more enumeration options after this script is completed" -ForegroundColor Cyan -BackgroundColor Black
$domain = Read-Host -Prompt 'Enter Domain Name (evilcorp)'
$path = Read-Host -Prompt 'Enter Path to Tools, used as output directory as well (C:\AzAD\Tools)'
Write-Host "Checking if output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain)){ New-Item -Path "$path\" -ItemType Directory -Name "AzAD_Assessment_$domain"}
$save = "$path\AzAD_Assessment_$domain\"
Write-Host
$user = Read-Host -Prompt 'Enter Username (user)'
$username = $user+"@"+$domain+".onmicrosoft.com"
$pass = Read-Host -Prompt 'Enter Password (SuperVeryEasyPAssw0rd)'
$passwd = ConvertTo-SecureString $pass -AsPlainText -Force 
$creds = New-Object System.Management.Automation.PSCredential ($username,$passwd)

#import modules needed
Write-Host
Write-Host "Importing Modules..." -ForegroundColor Cyan 
Import-Module $path\AADInternals\AADInternals.psd1
Import-Module $path\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1
Import-Module $path\AzureHound\AzureHound.ps1
Import-Module $path\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Import-Module $path\AzureADPreview\AzureADPreview.psd1
Write-Host "Completed." -ForegroundColor Red


#Enumeration - AzureAD Module

Write-Host
Write-Host "Getting Users, Groups, Devices and other Az/AzAD Resources with AzureAD Module" -ForegroundColor Green -BackgroundColor Black
Write-Host "Checking if AzureAD Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain\AzureAD)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AzureAD'}
$save = "$path\AzAD_Assessment_$domain\AzureAD\"
#First, connect to the tenant using the AzureAD module with credentials.
Connect-AzureAD -Credential $creds
Write-Host "AzureAD Users Enumeration" -ForegroundColor Cyan
Get-AzureADUser -ObjectId $username > $save\$user'_Azure-enumeration.txt'
#List all the attributes for a user
Get-AzureADUser -ObjectId $username | fl * > $save\$user'_attributes.txt'
Get-AzureADUser -ObjectId $username | %{$_.PSObject.Properties.Name} > $save\$user'_attributes2.txt'
#Objects owned by a specific user
Get-AzureADUserOwnedObject -ObjectId $username > $save\$user'_AzADObjectsCreatedByUser.txt'
#ROLES
Write-Host
Write-Host "AzureAD User Roles Enumeration" -ForegroundColor Cyan
#To list cutom roles, we need to use the AzureADPreview module:
Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName > $save\$user'_AzurecustomRoles.txt'
#GROUPS
Write-Host
Write-Host "AzureAD Groups Enumeration" -ForegroundColor Cyan
#Get groups and roles where the specified user is a member
Get-AzureADUserMembership -ObjectId $username > $save\$user_'AzureADCloudUserInfo.txt'
#DEVICES
Write-Host
Write-Host "AzureAD Devices Enumeration" -ForegroundColor Cyan
#List devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId $username > $save\$user'_OwnedDevice.txt'
#List devices registered by a user
Get-AzureADUserRegisteredDevice -ObjectId $username > $save\$user'_RegisteredDevice.txt'
#APPS
Write-Host
Write-Host "AzureAD Apps Enumeration" -ForegroundColor Cyan
#Get Apps where a User has a role (exact role is not shown)
Get-AzureADUser -ObjectId $username | Get-AzureADUserAppRoleAssignment | fl * > $save\$user'_RoleOnApp.txt'
Write-Host "Completed." -ForegroundColor Red


#Enumeration - Az PowerShell

Write-Host
Write-Host "Getting Users, Groups, Apps and Service Principals with Az PowerShell" -ForegroundColor Green -BackgroundColor Black
Write-Host
Write-Host "Checking if AzureAD Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain\AzPowerShell)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AzPowerShell'}
$save = "$path\AzAD_Assessment_$domain\AzPowerShell\"
#AAD USER
Write-Host
Write-Host "Az PowerShell (AAD) Users Enumeration" -ForegroundColor Cyan
#First, connect to the tenant using the Az PowerShell with credentials.
Connect-AzAccount -Credential $creds
#Enumerate a specific user
Get-AzADUser -UserPrincipalName $username > $save\$user'_Az-enumeration.txt'
#AAD GROUPS
Write-Host
Write-Host "Az PowerShell (AAD) Group Enumeration" -ForegroundColor Cyan
#List all the resources accessible to the current account:
Write-Host
Write-Host "Az PowerShell (AAD) List all the resources accessible to the current account" -ForegroundColor Cyan
Get-AzResource > $save\$user'_AzResource.txt'
#Get all the role assignments for the selected user:
Get-AzRoleAssignment -SignInName $username > $save\$user'_AzRoles.txt'
#Next, list all the VMs where the current user has at least the Reader role:
Get-AzVM | fl > $save\$user'_AzVMs.txt'
#List all App Services. We filter on the bases of 'Kind' proper otherwise both appservices and function apps are listed:
Get-AzWebApp | ?{$_.Kind -notmatch "functionapp"} > $save\$user'_AzAppServices.txt'
#To list Function Apps, use the below command:
Get-AzFunctionApp > $save\$user'_AzFunctionApp.txt'
#For the next task, list storage accounts:
Get-AzStorageAccount | fl > $save\$user'_AzStorageAccount.txt'
#Finally, list the readable keyvaults for the current user:
Get-AzKeyVault > $save\$user'_AzKeyVault.txt'
Write-Host "Completed." -ForegroundColor Red 


#Enumeration Azure CLI

Write-Host
Write-Host "Get user rights, app services/function apps, storage accounts and keyvault with Azure CLI" -ForegroundColor Green -BackgroundColor Black
Write-Host
Write-Host "Checking if AzureCLI Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain\AzureCLI)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AzureCLI'}
$save = "$path\AzAD_Assessment_$domain\AzureCLI\"
Write-Host
Write-Host "Azure CLI Enumeration" -ForegroundColor Cyan
#We first need to login to the target tenant using az cli. Use the below command for that:
az login -u $username -p $pass
#Next, list all the VMs where the current user has at least the Reader role.
az vm list > $save\$user'_cliVMs.txt'
#Here, we are only listing the 'name' of the VMs:
#az vm list --query "[].[name]" -o table
#List all App Services:
az webapp list > $save\$user'_cliAPPService.txt'
#List only the names of app services:
#az webapp list --query "[].[name]" -o table
#To list Function Apps, use the below command:
az functionapp list --query "[].[name]" -o table > $save\$user'_cliFunctionApp.txt'
#For the next task, list storage accounts:
az storage account list > $save\$user'_cliStorageAccountList.txt'
#Finally, list the readable keyvaults for the current user:
az keyvault list > $save\$user'_cliKEYVault.txt'
Write-Host "Completed." -ForegroundColor Red
