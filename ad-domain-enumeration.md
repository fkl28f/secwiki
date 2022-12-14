# AD - Domain Enumeration

Enumeration can be done by using Native executables, WMI and .NET classes.

**Basic Info of Domain (Forest/Domain Name, Domain Function Level etc.)**

$ADClass=\[System.DirectoryServices.ActiveDirectory.Domain]\
$ADclass::GetCurrentDomain()

**Tools**

* PowerView
  * cd C:\AD\Tools\\\
    . .\PowerView.ps1
* _Active Directory PowerShell Module_
  * Without RSAT and without local Admin is possible
  * Works fine with Constrained Language Mode
  * Microsoft Signed - low detection
  * cd C:\AD\Tools\ADModule-master\\\
    Import-Module .\Microsoft.ActiveDirectory.Management.dll\
    Import-Module .\ActiveDIrectory\ActiveDirectory.psd1   //Model + DLL, some Properties are not really good visible only with DLL

## **👓PowerView Basic Domain Enumeration**

**Get Current Domain**\
Get-NetDomain\
_Get-ADDomain_

**Get Object of another domain**\
Get-NetDomain -domain dom.local\
_Get-ADDomain -identity dom.local_

**Get domain SID for the current domain**\
Get-DomainSID\
_(Get-ADDomain).Domain.SID_

**Get the Domain Password Policy  / Kerberos Settings (MaxTicketAge, MaxServiceAge, MaxClockSkew, MaxRenewAge, TicketValidate Client)**\
****Get-DomainPolicy\
(Get-DomainPolicy)."System Access"   \
(Get-DomainPolicy)."Kerberos Policy"\
\
net accounts

## 👪 PowerView users groups and computers

**Get Information of domain controller DC**\
Get-NetDomainController\
Get-NetDomainController | select-object Name\
Get-NetDomainController -Domain mydom.local\
_Get-ADDomainController  //includes if LDAP/LDAPS Port Number_\
_Get-ADDomainController -DomainName moneycorp.local -Discover_

**Get information of users in the domain**\
****Get-NetUser\
Get-NetUser | select cn\
Get-NetUser -Username username1\
_Get-ADUser -Filter \* -Properties \*_\
_Get-ADUser -Filter \* -Properties \* | select Name_\
_Get-ADuser -Identity username1 -Properties \*_\


**Get list of all users**\
Get-NetUser | select samaccountname\
Get-NetUser -Username student1\
_Get-ADUser -Filter \* -Properties \*_ \
_Get-ADUser -Identity student1 -Properties \*_

**Get list of usernames, last logon and password last set** \
Get-NetUser | select samaccountname, lastlogon, pwdlastset Get-NetUser | select samaccountname, lastlogon, pwdlastset | Sort-Object -Property lastlogon

**Get list of usernames and their groups**\
Get-NetUser | select samaccountname, memberof

**Get list of all properties for users in the current domain**\
Get-Userproperty\
Get-Userproperty -Properties pwdlastset

_Get-ADUser -Filter \* -Properties \* | select -First 1 | Get-Member -MemberType \*Property | select Name_\
_Get-ADUser -Filter \* -Properties \* | select name,@{expression={\[datetime]::fromFileTime($\_.pwdlastset)\}}_

{% hint style="info" %}
Properties like badpwdcount, pwdlastset, logoncount help in identifying decoy objects / honeypots.

User may have some badpwdcount because he/she entered the wrong pw.
{% endhint %}

**❗ Get descripton field from the user / Search in user description** \
Find-UserField -SearchField Description -SearchTerm "built" \
Get-netuser | Select-Object samaccountname,description\
\
_Get-ADUser -Filter 'Description -like "\*built"' -Properties Description | select name,description_

&#x20;**List all groups of the domain** \
Get-NetGroup\
Get-NetGroup -FullData \
Get-NetGroup -GroupName _admin_ \
Get-NetGroup -Domain domainname

net group /domain

_Get-ADGroup -Filter \* | select Name_\
_Get-ADGroup -Filter \* -Properties \*_

**Get all the members of the group** \
Get-NetGroupMember -Groupname "Domain Admins" -Recurse\
Get-NetGroupMember -Groupname "Domain Admins" -Recurse | select MemberName\
Get-ADGroupMember -Identity "Domain Admins" -Recursive

{% hint style="info" %}
Renaming Domain Administrator: Does not matter because the MemberSID is \[DomainID]-\[UserID] - For the Administrator Account this is always UserID 500. It can not be changed.
{% endhint %}

**Get all the domain groups containing the word "admin" in group name**\
Get-NetGroup -GroupName \*_admin\*_\
_Get-ADGroup -Filter 'Name -like "admin"' | select Name_

{% hint style="info" %}
Enterprise Admin, Schema Admins, Enterprise Key Admins are missing from the result. They are only available on the Forest Root e.g. in the root domain.\
Get-NetGroup - Groupname \*admin\* -Domain rootdom.local
{% endhint %}

**Get the group membership of a user** \
Get-NetGroup -Username "username"\
_Get-ADPrincipalGroupMembership -Identity student1_

**List all the local groups on a machine (needs admin privs on non-dc machines)** \
Get-NetlocalGroup -Computername \[hostname] -ListGroups\
Get-NetlocalGroup -Computername DCHostnameHere -ListGroups

**Get Member of all the local groups on a machine (needs admin privs on non-dc machines)** \
Get-NetlocalGroup -Computername \[hostname] -Recurse

**Get actively logged users on a computer (needs local admin privs)** \
Get-NetLoggedon -Computername \[hostname]

**Get locally logged users on a computer (needs remote registry rights on the target - started by default on server os)** \
Get-LoggedonLocal -Computername \[hostname]

**Get the last logged users on a computer (needs admin rights and remote registary on the target)** \
****Get-LastLoggedOn -Computername \[hostname]

## **💻PowerView Computer**

**Get computer information** \
Get-NetComputer \
Get-NetComputer -FullData \
Get-NetComputer -OperatinSystem "\*Server 2016\*"\
Get-NetComputer -FullData | select opertingsystem\
Get-NetComputer -Ping\
\
_Get-ADComputer -Filter \* -Properties \*_\
_Get-ADComputer -Filter \* | select Name_\
_Get-ADComputer -Filter 'OperatingSystem -like "Server2016"' -Properties OperatingSystem | select Name, OperatingSystem_\
_Get-ADComputer -Filter \* -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $\_.DNSHostName}_\
__

**Get computers with operating system** \
Get-NetComputer -OperatingSystem "_Server 2016_"

**Get list of all computer names and operating systems** \
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion

****

## 📃 PowerView shares

**Find shared on hosts in the current domain** (readable or writeable ones)\
Invoke-ShareFinder -Verbose \
Invoke-ShareFinder -ExcludeStandard -ExcludePrint -ExcludeIPC

**Find sensitive files (PWs, Keys etc.) on computers in the domain** \
Invoke-FileFinder -Verbose

**Get all fileservers of the domain** (\
Get-NetFileServer -Verbose

{% hint style="info" %}
Searches for high value targets (machines/servers where lot of users authenticate to)\
E.g. Domain Controller, Fileserver Role installed, Exchange, Sharepoint
{% endhint %}



## 📕PowerView GPO

**Get list of GPO's in the current domain**\
Get-NetGPO\
Get-NetGPO | select displayname\
&#x20;  Default Domain Policy and Default Domain Controllers Policy are default ones\


**What GPO are applied to a certain machine**\
Get-NetGPO -Computername \[hostname] &#x20;

gpresult /R /V

**Get GPO's which uses restricteds groups or groups.xml for interesting users**\
Get-NetGPOGroup

{% hint style="info" %}
Restricted groups are those groups that are pushed through the group policy and are part of the local groups on your machine.
{% endhint %}

**Get users which are in a local group of a machine using GPO**\
Find-GPOComputerAdmin -Computername \[hostname]

**Get machines where the given user is member of a specific group using GPO**\
****Find-GPOLocation -Username \[username] -Verbose

**Get OU's in a domain**\
Get-NetOU -FullData\
_Get-ADOrganizationalUnit -Filter \* -Properties \*_

**Get machines that are part of an OU**\
Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $\_}

**Get GPO applied on an OU (take ID gplink from Get-NetGPO -Fulldata)** \
Get-NetGPO -GPOname '{ID...}'\
_Get-GPO -Guid ID_

## 🎰PowerView ACL

{% hint style="info" %}
**Access Control Model**

* Enables control on the ability of a process to access objects and the other resources in Active Directory based on :
  * Access Tokens (security context of a process - identity of the principal & privileges of a user) / The action of accessing
  * Security Descriptors (SID of the owner, Discretionary ACL (DACL - Who have what permissions) & System ACL (SACL - Audit Policy on the object)) / The Object you would like to access
  * Every Object has SACL, DACL, Owner - eg. Group "Domain Admins" DACL and every set Permission is an ACE\
    Both SACL and DACL are mde out of ACEs
{% endhint %}

{% hint style="info" %}
**Access Control List**

* List of Access Control Entries (ACE)
  * ACE corresponds to individual permission or audit access. (Who has permission and what can be done on an object?)
* Two types of ACLs :
* &#x20; DACL = Defines the permissions trustees (a user or group) have on an object.
* &#x20; SACL = logs success and failure audit messages when an object is accessed
* ACLs are vital to security architecture of an AD
{% endhint %}



![](<.gitbook/assets/image (1) (1).png>)

**Get the ACL's associated with the specified object**\
Get-ObjectACL -SamAccountName \[username] -ResolveGUIDS\
&#x20;  On the Object specified with ObjectDN, the User/Gorup specified in IdentityReference has the rights ActiveDirectoryRights.

**Get the ACL's associated with the specified prefix to be used for search**\
Get-ObjectACL -ADSprefix 'CN=Administrator,CN=Users' -Verbose \
Get-ObjectACL -ADSpath "LDAP://CN=Domain Admins,CN=Users,DC=test,DC=local" - ResolveGUID -Verbose\
\
_(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access  //no GUIDs will be provided_

**Get the ACL's associated with the specified path**\
****Get-PathAcl -Path "\\\ds-hostname\sysvol"

**Search for interesting ACL's (Write, modify etc.)**\
Invoke-ACLScanner -ResolveGUIDs \
Invoke-ACLScanner -ResolveGUIDs | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl

**Search of interesting ACL's for the current user** \
Invoke-ACLScanner | Where-Object {$\_.IdentityReference –eq \[System.Security.Principal.WindowsIdentity]::GetCurrent().Name}

## 🚥PowerView Domain trust

{% hint style="info" %}
**Trusts**

* In an AD environment, trust is a relationship between two domains or forests which allow users of one domain or forest to access resources in the other domain or forest.
* Trusts can be automatic (parent-child, root-leaf, same forest etc.) or established accross forest boundry (forest, external)
* Each Trust has a Trusted domain objects (TDOs) that represent the trust relationships in a domain&#x20;
{% endhint %}

{% hint style="info" %}
**Trust Directions**

* One-way trust : Unidirectional --> Users in the trusted domain can access resources in the trusting domain, but the reverse is not true.
* Bi-directional trust - Both Domain can access Ressources in the other Domain&#x20;

Trust Properties

*   Transitive trusts - The Trusts ca be extended to establish trust relationships with other domains e.g. Domain A to C via B

    All default intra-forest trust relationships (tree-root, parent-child) between domains within the same forest are transitive two-way trsuts
* Non-transitive trust - Cannot be extended to other domains in the forest. Can be two-way or one-way. This is default trust (called external trust) between two domains in different forests when forests do not have any trust relationship
{% endhint %}

![](<.gitbook/assets/image (3).png>)

{% hint style="info" %}
**Types of Trusts**

* Default / Automatic Trusts (Eg : Intra-forest trusts - two-way transitive trusts within a forest is default)
* Tree-Root Trust - When add a new domain to a forest/tree, this is also an automatic two-way transitive Trust
* Shortcut Trusts - Used to reduce access time in complex scenarios, Can be one or two way transitive
* External Trusts - b/w two domains in different forests when forests do not have a trust relationship. Can be one or two way and is always nontransitive (can not be changed).
* Forest trusts - b/w root domains of a forest. Can not be extended to a third forest (no implicit trust), can be one or two way and transitive or nontransitive
{% endhint %}

![](.gitbook/assets/image.png)



**Get a list of all the domain trusts for the current domain** \
Get-NetDomainTrust\
Get-NetDomainTrust -Domain domain.local\
_Get-ADTrust_ \
_Get-ADTrust -Filter \*_\
_Get-ADTrust -Identity  domain.local_

**Get details about the forest** \
Get-NetForest\
Get-NetForest -Forest forest.local\
_Get-ADForest_\
_Get-ADForest -Identity forest.local_

**❗Ge t all domains in the forest** \
Get-NetForestDomain \
Get-NetforestDomain -Forest forestname.local\
(_Get-ADForest).Domains_\
_Get-ADForest -Identity eurocorp.local_

**Get global catalogs for the current forest**\
Get-NetForestCatalog\
Get-NetForestCatalog -Forest forest.local\
Get-ADForest | select -ExpandProperty GlobalCatalogs

&#x20;**Map trusts of a forest**\
Get-NetForestTrust \
Get-NetForestTrust -Forest forest.local  \
Get-NetForestDomain -Verbose | Get-NetDomainTrust\
_Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'_

## 🔫User Hunting

**Find all machines on the current domain where the current user has local admin access / Contacting not only DC (noisy...)** \
****Find-LocalAdminAccess -Verbose

. ./Find-WMILocalAdminAccess.ps1\
Find-WMILocalAdminAccess\
Find-WMILocalAdminAccess - Computerfile computer.txt -verbose (all domain Computerhostnames from Get-NetComputer)

. ./Find-PSRemotingLocalAdminAccess.ps1\
Find-PSRemotingLocalAdminAccess



{% hint style="info" %}
This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess on each of those machines. Since this function is extremely noisy and can cause a network spike, it is better to run it in chunks of machines (using the option -ComputerFile) rather than all machines at once. The function leaves a 4624 (logon event) or 4634 (logoff event) for each machine on the domain.

This same function can also be done with the help of remote administration tools like WMI and powershell remoting. It is pretty useful in cases where ports of RPC and SMB (which are used by Find-LocalAdminAccess) are blocked. In such cases, you can use an alternate tool --> Find-WMILocalAdminAccess.ps1 (this is because, WMI by-default requires local admin access)
{% endhint %}

**Find local admins on all machines of the domain (needs admin privs on non-dc machines)** \
Invoke-EnumerateLocalAdmin -Verbose

{% hint style="info" %}
This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Get-NetLocalGroup on each machine.
{% endhint %}

**❗Find computers where a specified user/group (domain admins or RDPusers or etc.) has sessions (by-default Domain admins group) - and we have local admin on that machine**\
****Invoke-UserHunter -Verbose\
Invoke-UserHunter -GroupName "RDPUsers"

**Find active sessions of domain admins**\
****Invoke-UserHunter -Groupname "Domain Admins"

{% hint style="info" %}
This function queries the DC of the current or provided domain for members of the given group (Domain admins by default) using Get-NetGroupMember, gets a list of computers (Get-NetComputer) and list sessions and logged on users (Get-NetSession / Get-NetLoggedon) from each machine
{% endhint %}

**To find where our current user has local admin privs on servers that have domain admin sessions**\
Invoke-UserHunter -CheckAccess

**Find computers (high value targets) where a domain admin is logged-in**\
Invoke-UserHunter -Stealth

{% hint style="info" %}
This function queries the DC of the current or provided domain for members of the given group (Domain admins by default) using Get-NetGroupMember, gets a list of **only high value targets** (high traffic servers) - DC, File servers & distributed file servers, for being stealthy and generating lesser traffic and lists sessions and logged on users (Get-NetSession / Get-NetLoggedon) from each machine
{% endhint %}

**Manually get Sessions of a Computer**\
****Get-NetSession -Computername hostname.local

****

## **🛡Defense against Enumeration / User Hunting**

{% hint style="info" %}
Most enumeration mixes well with legit traffic!

Monitor for certain windows events which are an anomaly (lots of requests from one source).

NetCease is a script that changes permissions on the NetSessionEnum method by removing permission for Authenticated Users group.

This fails many of the attacker's session enumeration and hence user hunting capabilities - but it will break stuff!

.\NetCease.ps1\
Restart-Service -Name Server -Force

To revert back to pre-netcease state:\
.\NetCease.ps1 -Revert \
Restart-Service -Name Server -Force


{% endhint %}

{% hint style="info" %}
Another intersting script is SAMRi10 which hardens W10 and Server 2016 against enumeration which uses SAMR protocol (like net.exe)
{% endhint %}



****





__
