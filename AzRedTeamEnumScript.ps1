#Azure AD RedTeam Full Enum Script
#created by n3t1nv4d3
#July 27, 2021


$logo=@"
    ___      ___    ___   ______ ______      __      
   /   |____/   |  / __| / __  /_    _/__   /  \   ____  ______
  / /| |__ /  - | / /_  / / / /  |  |/ _ \ / /\ \ / __ \/ __  /
 / ___ |/ / / \ \/ /__ / /_/ /   |  || __// ___  \ / / / / / /  
/_/  |_/___/  |_/_____/_____/    \__/\___/_/   \__/ /___/ /_/
  
 Azure AD Enumeration Script by @n3t1nv4d3
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
Import-Module $path\AADInternals\AADInternals.psd1  #OR Install-Module AADInternals
Import-Module $path\MicroBurst\Misc\Invoke-EnumerateAzureBlobs.ps1
Invoke-WebRequest -Uri https://aka.ms/installazurecliwindows -OutFile .\AzureCLI.msi; Start-Process msiexec.exe -Wait -ArgumentList '/I AzureCLI.msi /quiet'; rm .\AzureCLI.msi  #Azure CLI
Import-Module $path\AzureHound\AzureHound.ps1
Import-Module $path\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Import-Module $path\AzureADPreview\AzureADPreview.psd1 #OR Install-module AzureADPreview 
Write-Host "Completed." -ForegroundColor Red



#Enumeration - AzureAD Module

Write-Host
Write-Host "Getting Users, Groups, Devices and other Az/AzAD Resources with AzureAD Module" -ForegroundColor Green -BackgroundColor Black
Write-Host "Checking if AzureAD Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain\AzureAD)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AzureAD'}
$save = "$path\AzAD_Assessment_$domain\AzureAD\"
#First, connect to the tenant using the AzureAD module with credentials.
Connect-AzureAD -Credential $creds
#Get the current session state
Get-AzureADCurrentSessionInfo > $save\AzureADCurrentSessionInfo.txt
#Get details of the current tenant
Get-AzureADTenantDetail > $save\AzureADTenantDetail.txt
#Check if users are allowed to consent to apps
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole > $save\ConsentToApps.txt

#USERS
Write-Host
Write-Host "AzureAD Users Enumeration" -ForegroundColor Cyan
#To enumerate all users, use the below command:
Get-AzureADUser -All $true > $save\FullAzureADUser.txt
#To list only the UPNs of the users, use the below command:
Get-AzureADUser -All $true | select UserPrincipalName > $save\AzureADUser.txt
#Enumerate specific user
Get-AzureADUser -ObjectId $username > $save\$user'_Azure-enumeration.txt'
#Search for a user based on string in first characters of DisplayName or userPrincipalName (wildcard not supported)
Get-AzureADUser -SearchString "admin" > $save\AzureADadminUsers.txt
#List all the attributes for a user
Get-AzureADUser -ObjectId $username | fl * > $save\$user'_attributes.txt'
Get-AzureADUser -ObjectId $username | %{$_.PSObject.Properties.Name} > $save\$user'_attributes2.txt'
#Search attributes for all users that contain the string "password" - feel free to change this value
Get-AzureADUser -All $true |%{$Properties = $_;$Properties.PSObject.Properties.Name | % {if ($Properties.$_ -match 'password') {"$($Properties.UserPrincipalName) - $_ - $Properties.$_)"}}} > $save\AzureADUsersAttributesPassword.txt
#All users who are synced from on-prem
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -ne $null} > $save\AzADSyncedOn-PermUsers.txt
#All users who are from Azure AD
Get-AzureADUser -All $true | ?{$_.OnPremisesSecurityIdentifier -eq $null} > $save\AzADCloudUsers.txt
#Objects created by any user (use -ObjectId for a specific user)
Get-AzureADUser | Get-AzureADUserCreatedObject > $save\AzADObjectsCreatedByAnyUser.txt
#Objects owned by a specific user
Get-AzureADUserOwnedObject -ObjectId $username > $save\$user'_AzADObjectsCreatedByUser.txt'
#To get all the Global Administrators, use the below command:
Get-AzureADDirectoryRole -Filter "DisplayName eq 'Global Administrator'" | Get-AzureADDirectoryRoleMember > $save\globalAdmins.txt
Write-Host "Completed." -ForegroundColor Red

#ROLES
Write-Host
Write-Host "AzureAD Roles Enumeration" -ForegroundColor Cyan
#Get all available role templates
Get-AzureADDirectoryroleTemplate > $save\AzureADDirectoryroleTemplate.txt
#Get all roles
Get-AzureADDirectoryRole > $save\AzureADDirectoryRole.txt
#To list cutom roles, we need to use the AzureADPreview module:
Get-AzureADMSRoleDefinition | ?{$_.IsBuiltin -eq $False} | select DisplayName > $save\$user'_AzurecustomRoles.txt'
Write-Host "Completed." -ForegroundColor Red

#GROUPS
Write-Host
Write-Host "AzureAD Groups Enumeration" -ForegroundColor Cyan
#To list all the groups, use the below command:
Get-AzureADGroup -All $true > $save\AzureADGroup.txt
#Enumerate a specific group
#Get-AzureADGroup -ObjectId 984a312d-0de2-4490-92e4-539b0e4ee03e
#Search for a group based on string in first characters of DisplayName (wildcard not supported)
Get-AzureADGroup -SearchString "admin" | fl * > $save\AzureADadminGroups.txt
#To search for groups which contain the word "admin" in their name, feel free to change the value:
Get-AzureADGroup -All $true |?{$_.Displayname -match " admin"} > $save\AzureADadminGroups2.txt
#Get Groups that allow Dynamic membership (Note the cmdlet name)
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'} > $save\AzureDynamicGroups.txt
#All groups that are synced from on prem (note that security groups are not synced)
Get-AzureADGroup -All $true |?{$_.OnPremisesSecurityIdentifier -ne $null} > $save\AzureADSyncedOn-PermGroups.txt
#All groups that are from Azure AD
Get-AzureADGroup -All $true |?{$_.OnPremisesSecurityIdentifier -eq $null} > $save\AzureADCloudGroups.txt
#Get members of a group
#Get-AzureADGroupMember -ObjectId 984a312d-0de2-4490-92e4-539b0e4ee03e
#Get groups and roles where the specified user is a member
Get-AzureADUserMembership -ObjectId $username > $save\$user_'AzureADCloudUserInfo.txt'
Write-Host "Completed." -ForegroundColor Red

#DEVICES
Write-Host
Write-Host "AzureAD Devices Enumeration" -ForegroundColor Cyan
#Get all Azure joined and registered devices
Get-AzureADDevice -All $true | fl * > $save\AzureADDevice.txt
#Get the device configuration object (note the RegistrationQuota in the output)
Get-AzureADDeviceConfiguration | fl * > $save\AzureADDeviceConfiguration.txt
#List Registered owners of all the devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredOwner > $save\AzureADDeviceRegisteredOwner.txt
#List Registered users of all the devices
Get-AzureADDevice -All $true | Get-AzureADDeviceRegisteredUser > $save\AzureADDeviceRegisteredUser.txt
#List devices owned by a user
Get-AzureADUserOwnedDevice -ObjectId $username > $save\$user'_OwnedDevice.txt'
#List devices registered by a user
Get-AzureADUserRegisteredDevice -ObjectId $username > $save\$user'_RegisteredDevice.txt'
#List devices managed using Intune
Get-AzureADDevice -All $true | ?{$_.IsCompliant -eq "True"} > $save\IntuneAzureADDevice.txt
Write-Host "Completed." -ForegroundColor Red

#APPS
Write-Host
Write-Host "AzureAD Apps Enumeration" -ForegroundColor Cyan
#Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
Get-AzureADApplication -All $true > $save\AzureADApplication.txt
#Get all details about an application
#Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0  | fl *
#Get an application based on the display name
Get-AzureADApplication -All $true | ?{$_.DisplayName -match "app"} > $save\AzureADApplicationSearch.txt
#The Get-AzureADApplicationPasswordCredential will show the applications with an application password but password value is not shown.
#Get-AzureADApplicationPasswordCredential > $save\AzureADApplicationPasswordCredential.txt
#Get owner of an application
#Get-AzureADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0 | Get-AzureADApplicationOwner |fl *
#Get Apps where a User has a role (exact role is not shown)
Get-AzureADUser -ObjectId $username | Get-AzureADUserAppRoleAssignment | fl * > $save\$user'_RoleOnApp.txt'
#Get Apps where a Group has a role (exact role is not shown)
#Get-AzureADGroup -ObjectId 783a312d-0de2-4490-92e4-539b0e4ee03e | Get-AzureADGroupAppRoleAssignment | fl *
Write-Host "Completed." -ForegroundColor Red

#SERVICE PRINCIPALS
Write-Host
Write-Host "AzureAD Service Principals Enumeration" -ForegroundColor Cyan
#Get all service principals
Get-AzureADServicePrincipal -All $true > $save\AzureADServicePrincipal.txt
#Get all details about a service principal
#Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264  | fl *
#Get an service principal based on the display name
Get-AzureADServicePrincipal -All $true | ?{$_.DisplayName -match "app"} > $save\AzureADServicePrincipalSearch.txt
#Get owner of a service principal
#Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45- 053e7c37a264 | Get-AzureADServicePrincipalOwner |fl *
#Get objects owned by a service principal
#Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45- 053e7c37a264 | Get-AzureADServicePrincipalOwnedObject
#Get objects created by a service principal
#Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalCreatedObject
#Get group and role memberships of a service principal
#Get-AzureADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264 | Get-AzureADServicePrincipalMembership |fl *
Get-AzureADServicePrincipal | Get-AzureADServicePrincipalMembership > $save\AzureADServicePrincipalMembership.txt
Write-Host "Completed." -ForegroundColor Red




#Enumeration - Az PowerShell
#Install-Module Az

Write-Host
Write-Host "Getting Users, Groups, Apps and Service Principals with Az PowerShell" -ForegroundColor Green -BackgroundColor Black
Write-Host
Write-Host "Checking if AzureAD Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AzAD_Assessment_$domain\AzPowerShell)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AzPowerShell'}
$save = "$path\AzAD_Assessment_$domain\AzPowerShell\"
#First, connect to the tenant using the Az PowerShell with credentials.
Connect-AzAccount -Credential $creds

#AAD USER
Write-Host
Write-Host "Az PowerShell (AAD) Users Enumeration" -ForegroundColor Cyan
#Enumerate all users
Get-AzADUser > $save\AzADUser.txt
#Enumerate a specific user
Get-AzADUser -UserPrincipalName $username > $save\$user'_Az-enumeration.txt'
#Search for a user based on string in first characters of DisplayName (wildcard not supported)
Get-AzADUser -SearchString "admin" > $save\AzAdminSearch.txt
#Search for users who contain the word "admin" in their Display name:
Get-AzADUser |?{$_.Displayname -match "admin"} > $save\AzAdminSearch2.txt
Write-Host "Completed." -ForegroundColor Red

#AAD GROUPS
Write-Host
Write-Host "Az PowerShell (AAD) Group Enumeration" -ForegroundColor Cyan
#List all groups
Get-AzADGroup > $save\AzADGroup.txt
#Enumerate a specific group
#Get-AzADGroup -ObjectId 984a312d-0de2-4490-92e4-539b0e4ee03e
#Search for a group based on string in first characters of DisplayName (wildcard not supported)
Get-AzADGroup -SearchString "admin" | fl * > $save\AzADGroupAdminSearch.txt
#To search for groups which contain the word "admin" in their name:
Get-AzADGroup |?{$_.Displayname -match "admin"} > $save\AzADGroupAdminSearch2.txt
#Get members of a group
#Get-AzADGroupMember -ObjectId 984a312d-0de2-4490-92e4-539b0e4ee03e
Write-Host "Completed." -ForegroundColor Red

#AAD APPS
Write-Host
Write-Host "Az PowerShell (AAD) Apps Enumeration" -ForegroundColor Cyan
#Get all the application objects registered with the current tenant (visible in App Registrations in Azure portal). An application object is the global representation of an app.
Get-AzADApplication > $save\AzADApplication.txt
#Get all details about an application
#Get-AzADApplication -ObjectId a1333e88-1278-41bf-8145-155a069ebed0
#Get an application based on the display name
Get-AzADApplication | ?{$_.DisplayName -match "app"} > $save\AzADApplicationSearch.txt
Write-Host "Completed." -ForegroundColor Red

#AAD SERVICE PRINCIPAL
Write-Host
Write-Host "Az PowerShell (AAD) Service Principal Enumeration" -ForegroundColor Cyan
#Enumerate Service Principals (visible as Enterprise Applications in Azure Portal). Service principal is local representation for an app in a specific tenant and it is the security object that has privileges. 
#This is the 'service account'! Get all service principals:
Get-AzADServicePrincipal > $save\AzADServicePrincipal.txt 
#Get all details about a service principal
#Get-AzADServicePrincipal -ObjectId cdddd16e-2611-4442-8f45-053e7c37a264
#Get an service principal based on the display name
Get-AzADServicePrincipal | ?{$_.DisplayName -match "app"} > $save\AzADServicePrincipalSearch.txt
Write-Host "Completed." -ForegroundColor Red

#List all the resources accessible to the current account:
Write-Host
Write-Host "Az PowerShell (AAD) List all the resources accessible to the current account" -ForegroundColor Cyan
Get-AzResource > $save\$user'_AzResource.txt'
#Get all the role assignments for the test user:
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
 


#AADInternals

Write-Host
Write-Host "Get tenant name, authentication, brand name and domain name with AADInternals" -ForegroundColor Green -BackgroundColor Black
Write-Host
Write-Host "Checking if AzureAD Module output directory exists" -ForegroundColor Cyan
if(!(Test-Path $path\AAzAD_Assessment_$domain\AADInternals)){ New-Item -Path "$path\AzAD_Assessment_$domain" -ItemType Directory -Name 'AADInternals'}
$save = "$path\AzAD_Assessment_$domain\AADInternals\"
Get-AADIntLoginInformation -UserName admin@$domain.onmicrosoft.com
Get-AADIntLoginInformation -UserName $username > $save\ADDInternals.txt
Write-Host
Write-Host "Get Tenant ID" -ForegroundColor Cyan

#To get the Tenant ID, use the below command:
Get-AADIntTenantID -Domain $domain'.onmicrosoft.com' > $save\AADIntTenantID.txt
Write-Host "Completed." -ForegroundColor Red
Write-Host
Write-Host "Get Tenant Domains" -ForegroundColor Cyan

#To get the Tenant Domains, use the below command:
Get-AADIntTenantDomains -Domain $domain'.onmicrosoft.com' > $save\AADIntTenantDomains.txt
Write-Host "Completed." -ForegroundColor Red
Write-Host
Write-Host "Get Tenant Information" -ForegroundColor Cyan

#To get the Tenant Domains, use the below command:
Invoke-AADIntReconAsOutsider -DomainName $domain'.onmicrosoft.com' > $save\AADIntReconAsOutsider.txt
Write-Host "Completed." -ForegroundColor Red



#Azure Blob Enumeration

Write-Host
Write-Host "Azure Storage Accounts Enumeration" -ForegroundColor Green -BackgroundColor Black
Write-Host
$save = "$path\AzAD_Assessment_$domain\"
#We will use MicroBurt for enumerating storage accounts in the target tenant.
#We need to add permutations like common, backup, code C:\AzAD\Tools\Microburst\Misc\permutations.txt to tune it for target scope.
Invoke-EnumerateAzureBlobs -Base $domain -OutputFile $save\AzBlobs.txt
Write-Host "Completed." -ForegroundColor Red



#BloodHound

Write-Host
Write-Host "BloodHound Running" -ForegroundColor Green -BackgroundColor Black
Write-Host
$save = "$path\AzAD_Assessment_$domain\"
#Now, let's load AzureHound and run it:
Invoke-AzureHound -Verbose -OutputDirectory $save
Write-Host "Completed." -ForegroundColor Red



#SubDomain Enumeration

Write-Host
Write-Host "SubDomain Enumeration" -ForegroundColor Green -BackgroundColor Black
Write-Host
$save = "$path\AzAD_Assessment_$domain\"
#To enumerate services used by the target tenant, we can use subdomain guessing using MicroBurst. The below command will take a few miuntes to complete:
Invoke-EnumerateAzureSubDomains -Base $domain -Verbose > $save\subdomains.txt
Write-Host "Completed." -ForegroundColor Red