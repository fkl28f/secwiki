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

**Get Current Domain & DC name**

```powershell
Get-NetDomain
Get-NetDomain -domain dom.local
Get-ADDomain
Get-ADDomain -identity dom.local
```

**Get domain SID for the current domain**

```powershell
Get-DomainSID
(Get-ADDomain).Domain.SID
```

**Get Domaincontroller**

<pre class="language-powershell"><code class="lang-powershell">Get-DomainController
<strong>Get-DomainController -domain test.local
</strong></code></pre>

**Get Overview of all Trusts**

```powershell
Invoke-MapDomainTrust
```

**Get the Domain Password Policy  / Kerberos Settings (MaxTicketAge, MaxServiceAge, MaxClockSkew, MaxRenewAge, TicketValidate Client)**

```powershell
Get-DomainPolicy
(Get-DomainPolicy)."System Access"   
(Get-DomainPolicy)."Kerberos Policy"

net accounts
```

## 👪 PowerView users groups and computers

**Get Information of domain controller DC**

```powershell
Get-NetDomainController
Get-NetDomainController | select-object Name
Get-NetDomainController -Domain mydom.local
Get-ADDomainController  //includes if LDAP/LDAPS Port Number
Get-ADDomainController -DomainName moneycorp.local -Discover
```

**Get information of users in the domain**

```powershell
Get-DomainUser
Get-DomainUser student1
Get-DomainUser -domain otherdom.local
Get-NetUse username1
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter * -Properties * | select Name
Get-ADuser -Identity username1 -Properties *Get-domain 
```

**Get list of usernames, last logon and password last set**&#x20;

{% code overflow="wrap" %}
```powershell
Get-DomainUser | select samaccountname, lastlogon, pwdlastset, logoncount | Sort-Object -Property lastlogon
Get-NetUser | select samaccountname, lastlogon, pwdlastset, logoncount | Sort-Object -Property lastlogon

```
{% endcode %}

**Get list of usernames and their groups**

```powershell
Get-DomainUser | select samaccountname, memberof
Get-NetUser | select samaccountname, memberof 
```

**Get list of all properties for users in the current domain**

{% code overflow="wrap" %}
```powershell
Get-ADUser -Filter * -Properties * | select -First 1 | Get-Member -MemberType *Property | select Name
Get-ADUser -Filter * -Properties * | select name,@{expression={[datetime]::fromFileTime($_.pwdlastset)}}
```
{% endcode %}

~~Get-Userproperty~~\
~~Get-Userproperty -Properties pwdlastset~~

{% hint style="info" %}
Properties like badpwdcount, pwdlastset, logoncount help in identifying decoy objects / honeypots.

User may have some badpwdcount because he/she entered the wrong pw.
{% endhint %}

**❗ Get descripton field from the user / Search in user description**&#x20;

```powershell
Get-DomainUser -LDAPFilter "Description=*built*" | Select name, description

Get-ADUser -Filter 'Description -like "*built"' -Properties Description | select name,description
```

**Convert SID to Username / Name**

<pre class="language-powershell"><code class="lang-powershell">"S-1-5-21-3146393536-1393405867-2905981701-1000" | convert-sidtoname
<strong>-or-
</strong><strong>$SID ='S-1-5-21-1924530255-1943933946-939161726-500'
</strong>$objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
$objUser = $objSID.Translate([System.Security.Principal.NTAccount])
Write-Host "Resolved user name: " $objUser.Value
</code></pre>

**Convert Username to SID**

```powershell
Convert-NameToSID

$user ='TestDomainMorgan'
$objUser = New-Object System.Security.Principal.NTAccount($user)
$objSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
Write-Host "Resolved user's sid: " $objSID.Value
```

**List all groups of the domain**&#x20;

<pre class="language-powershell"><code class="lang-powershell">Get-DomainGroup | select Name
Get-DomainGroup -domain target.dom
Get-NetGroup
Get-NetGroup -FullData 
Get-NetGroup -GroupName admin 
Get-NetGroup -Domain domainname
net group /domain
<strong>
</strong><strong>Get-ADGroup -Filter * | select Name
</strong>Get-ADGroup -Filter * -Properties *
</code></pre>

**Get all the members of the group**

<pre class="language-powershell"><code class="lang-powershell">Get-DomainGroupMember -identity "Domain Admins" -Recurse
Get-NetGroupMember "Domain Admins" -Recurse
Get-NetGroupMember "Domain Admins" -Recurse | select MemberName
<strong>
</strong><strong>Get-ADGroupMember -Identity "Domain Admins" -Recursive
</strong></code></pre>

{% hint style="info" %}
Renaming Domain Administrator: Does not matter because the MemberSID is \[DomainID]-\[UserID] - For the Administrator Account this is always UserID 500. It can not be changed.
{% endhint %}

**Get all the domain groups containing the word "admin" in group name**

<pre class="language-powershell"><code class="lang-powershell">Get-DomainGroup *admin*
Get-NetGroup  *admin*
<strong>
</strong><strong>Get-ADGroup -Filter 'Name -like "admin"' | select Name
</strong></code></pre>

{% hint style="info" %}
Enterprise Admin, Schema Admins, Enterprise Key Admins are missing from the result. They are only available on the Forest Root e.g. in the root domain.\
Get-NetGroup - Groupname \*admin\* -Domain rootdom.local
{% endhint %}

**Get the group membership of a user (not recursively)**

```powershell
Get-DomainGroup -Username "username"
Get-NetGroup -Username "username"

Get-ADPrincipalGroupMembership -Identity student1 
```

**Get the group membership of a user recursively!**&#x20;

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Import-Module .\Microsoft.ActiveDirectory.Management.dll -Verbose
<strong>Import-Module .\ActiveDirectory\ActiveDirectory.psd1
</strong><strong>Import-Module .\Get-ADPrincipalGroupMembershipRecursive.ps1
</strong>
Content of Get-ADPrincipalGroupMembershipRecursive.ps1:
function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName)
{
 $groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName |
select -ExpandProperty distinguishedname)
 $groups
 if ($groups.count -gt 0)
 {
 foreach ($group in $groups)
 {
 Get-ADPrincipalGroupMembershipRecursive $group
 }
 }
}

Then run:
Get-ADPrincipalGroupMembershipRecursive 'studentuserx'

<strong>- OR -
</strong>https://gist.githubusercontent.com/paulfijma/2beb3517203c34e63957fbffd1c877c2/raw/42e99ff2f734c98b604a30366cca00f9498942d6/Get-ADPrincipalGroupMembershipRecursive.ps1
</code></pre>

**Add a User to a Group**

```powershell
Add-ADGroupMember -Identity GroupNameHere -Members studentuserx -Verbose
```

**List all the local groups on a machine (needs admin privs on non-dc machines)**

```powershell
Get-NetlocalGroup -Computername [hostname]
```

**Get Member of all the local groups "Administrators" on a machine (needs admin privs on non-dc machines)**&#x20;

```powershell
Get-NetLocalGroupMember -Computername [hostname] -GroupName Administrators 
```

**Get actively logged users on a computer (needs local admin privs)**&#x20;

```powershell
Get-NetLoggedOn -Computername [hostname]
```

**Get locally logged users on a computer (needs remote registry rights on the target - started by default on server os)**&#x20;

```powershell
Get-dGet-LoggedOnLocal -Computername [hostname] 
```

**Get the last logged users on a computer (needs admin rights and remote registary on the target)**&#x20;

```powershell
Get-LastLoggedOn -Computername [hostname]
```



## **💻PowerView Computer**

**Get computer information**&#x20;

{% code overflow="wrap" %}
```powershell
Get-DomainComputer
Get-DomainComputer -OperatingSystem "*Server 2016*"
Get-DomainComputer | select name
Get-DomainComputer | select operatingsystem
Get-DomainComputer | select operatingsystem

All computers within an OU
Get-DomainComputer -SearchBase "LDAP://OU=ouname,DC=sub,DC=dom,DC=local"

Get-NetComputer -ping
Get-NetComputer -FullData 
Get-NetComputer -OperatingSystem "*Server 2016*"
Get-NetComputer -FullData | select opertingsystem
Get-NetComputer -Ping

//
Get-ADComputer -Filter * -Properties *
Get-ADComputer -Filter * | select Name
Get-ADComputer -Filter 'OperatingSystem -like "Server2016"' -Properties OperatingSystem | select Name, OperatingSystem
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName}
```
{% endcode %}

**Get list of all computer names and operating systems**&#x20;

{% code overflow="wrap" %}
```powershell
Get-NetComputer -fulldata | select samaccountname, operatingsystem, operatingsystemversion 
```
{% endcode %}

\
📃 PowerView shares
-------------------

**Find shared on hosts in the current domain** (readable or writeable ones)

```powershell
Invoke-ShareFinder -Verbose -CheckShareAccess

Invoke-ShareFinder -Verbose //does not check access of your user
```

**Find sensitive files (PWs, Keys etc.) on computers in the domain**&#x20;

```powershell
Invoke-FileFinder -Verbose 
```

**Get all fileservers of the domain**

```powershell
Get-NetFileServer -Verbose 
```

{% hint style="info" %}
Searches for high value targets (machines/servers where lot of users authenticate to)\
E.g. Domain Controller, Fileserver Role installed, Exchange, Sharepoint
{% endhint %}



## 📕PowerView GPO

**Get list of GPO's in the current domain**

```powershell
Get-DomainGPO
Get-DomainGPO | select displayname
Get-DomainGPO -domain otherdom.local
Get-NetGPO
Get-NetGPO | select displayname
   Default Domain Policy and Default Domain Controllers Policy are default ones 
```

**What GPO are applied to a certain machine**

```powershell
Get-DomainGPO -computeridentity hostname
Get-NetGPO -Computername [hostname]  

gpresult /R /V
```

**Get GPO's which uses restricteds groups or groups.xml for interesting users**

```powershell
Get-DomainGPOLocalGroup
Get-NetGPOGroup
```

{% hint style="info" %}
Restricted groups are those groups that are pushed through the group policy and are part of the local groups on your machine.
{% endhint %}

**Get users which are in a local group of a machine using GPO**

```powershell
Get-DomainGPOComputerLocalGroupMapping -computeridentity hostname
Find-GPOComputerAdmin -Computername [hostname]
```

**Get machines where the given user is member of a specific group using GPO**

```powershell
Get-DomainGPOUserLocalGroupMapping -identity user1 -verbose
Find-GPOLocation -Username [username] -Verbose
```

**Get OU's in a domain**

```powershell
Get-DomainOU
Get-NetOU -FullData

Get-ADOrganizationalUnit -Filter * -Properties *
```

**Get machines that are part of an OU**

{% code overflow="wrap" %}
```powershell
Get-DomainOU ouname 
Get-DomainOU ouname | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name}
```
{% endcode %}

\
**Get GPO applied on an OU (take ID gplink get-netou)**&#x20;

```powershell
Get-DomainGPO -identity '{id...}'

Get-GPO -Guid ID 
```

**Enumerate permissions for GPOs where users with RIDs of > 1000 have some kind of modification/control rights**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-DomainObjectAcl -LDAPFilter '(objectCategory=groupPolicyContainer)' | ? { ($_.SecurityIdentifier -match '^S-1-5-.*-[1-9]\d{3,}$') -and ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|WriteDacl|WriteOwner')} | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
</strong></code></pre>



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



![](<.gitbook/assets/image (1) (1) (1).png>)

**Get the ACL's associated with the specified object**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-DomainObjectACL -SamAccountName [username] -ResolveGUIDS
Get-ObjectACL -SamAccountName [username] -ResolveGUIDS
<strong>
</strong><strong>Read it like that: On the Object specified with ObjectDN, the User/Gorup specified in IdentityReference has the rights ActiveDirectoryRights.
</strong></code></pre>

**Get the ACL's associated with the specified prefix to be used for search**

{% code overflow="wrap" %}
```powershell
Get-DomainObjectAcl -SearchBase "LDAP://CN=Domain Admins,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local" -ResolveGUIDs -Verbose

Get-DomainObjectAcl -Identity "Domain Admins" -ResolveGUIDs –Verbose

(Get-Acl 'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access  //no GUIDs will be provided
```
{% endcode %}

**Search for interesting ACL's (Write, modify etc.)**

{% code overflow="wrap" %}
```powershell
❗Find-InterestingDomainAcl -ResolveGUIDs

Find-InterestingDomainAcl -RightsFilter All
Find-InterestingDomainAcl -RightsFilter ResetPassword
Find-InterestingDomainAcl -RightsFilter WriteMember
Invoke-ACLScanner -ResolveGUIDs 
Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl 
```
{% endcode %}

**❗Search of interesting ACL's for the current user (or where the current is memberOf**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Invoke-aclscanner -resolveguids | ?{$_.IdentityReferenceName -match "yout-username"}
</strong>Invoke-aclscanner -resolveguids | ?{$_.IdentityReferenceName -match "hostname$"}
Invoke-aclscanner -resolveguids | ?{$_.IdentityReferenceName -match "your-member-of-group-name"}

Invoke-aclscanner -resolveguids | ?{$_.IdentityReferenceName -match "RDPUsers"} | select Object DN,ActiveDirectoryRights,IdentityReferenceName

Find-InterestingDomainAcl | Where-Object {$_.IdentityReference –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}

Invoke-ACLScanner | Where-Object {$_.IdentityReferenceName –eq [System.Security.Principal.WindowsIdentity]::GetCurrent().Name}
</code></pre>

**Get the ACL's associated with the specified path**

```powershell
Get-PathAcl -Path "\\ds-hostname\sysvol"
```

**Search / Add if User has DCSync Rights**

{% code overflow="wrap" %}
```powershell
Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}

Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | ?{$_.IdentityName -match "studentx"}
```
{% endcode %}

**Add DCSync Rights**

{% code overflow="wrap" %}
```powershell
Add-DomainObjectAcl -TargetIdentity 'DC=dollarcorp,DC=moneycorp,DC=local' -PrincipalIdentity studentx -Rights DCSync -PrincipalDomain dollarcorp.moneycorp.local -TargetDomain dollarcorp.moneycorp.local -Verbose
```
{% endcode %}

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

![](<.gitbook/assets/image (9) (1).png>)

{% hint style="info" %}
**Types of Trusts**

* Default / Automatic Trusts (Eg : Intra-forest trusts - two-way transitive trusts within a forest is default)
* Tree-Root Trust - When add a new domain to a forest/tree, this is also an automatic two-way transitive Trust
* Shortcut Trusts - Used to reduce access time in complex scenarios, Can be one or two way transitive
* External Trusts - b/w two domains in different forests when forests do not have a trust relationship. Can be one or two way and is always nontransitive (can not be changed).
* Forest trusts - b/w root domains of a forest. Can not be extended to a third forest (no implicit trust), can be one or two way and transitive or nontransitive
{% endhint %}

![](<.gitbook/assets/image (8) (1).png>)



**Get a list of all the domain trusts for the current domain**&#x20;

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-DomainTrust | ft
Get-DomainTrust -domain dom.local
Get-NetDomainTrust
Get-NetDomainTrust -Domain domain.local

Get-ADTrust 
<strong>❗Get-ADTrust -Filter *
</strong><strong>  SIDFilteringForestAware is set to True, it means SIDHistory is enabled across the forest trust.
</strong>Get-ADTrust -Identity  domain.local
</code></pre>

**Get details about the forest**&#x20;

<pre class="language-powershell"><code class="lang-powershell">Get-Forest
Get-Forest -forest forestname.local
Get-NetForest
Get-NetForest -Forest forest.local
<strong>
</strong><strong>Get-ADForest
</strong>Get-ADForest -Identity forest.local
</code></pre>

**❗Ge t all domains in the current/other forest**&#x20;

```powershell
Get-ForestDomain -verbose
Get-ForestDomain -Forest forest.local
Get-NetForestDomain 
Get-NetforestDomain -Forest forestname.local

(Get-ADForest).Domains
Get-ADForest -Identity eurocorp.local
```

**❗❗ Get all domains in the current /other forest & trusts**

```powershell
Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name}
Get-ForestDomain -forest otherforest.local | %{Get-DomainTrust -Domain $_.Name}
```

**List only external trusts for one forest and all its domains**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-ForestDomain | %{Get-DomainTrust -Domain $_.Name} | ?{$_.TrustAttributes -eq "FILTER_SIDS"}
</strong>(Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)'
</code></pre>

**Get global catalogs for the current forest**

<pre class="language-powershell"><code class="lang-powershell">Get-ForestGlobalCatalog
Get-ForestGlobalCatalog -forest forest.local
Get-NetForestCatalog
Get-NetForestCatalog -Forest forest.local
<strong>
</strong><strong>Get-ADForest | select -ExpandProperty GlobalCatalogs
</strong></code></pre>

&#x20;**Map trusts of a forest**

<pre class="language-powershell"><code class="lang-powershell">Get-ForestTrust
<strong>Get-ForestTrust -Forest forest.local
</strong>Get-NetForestTrust 
Get-NetForestTrust -Forest forest.local
Get-NetForestDomain -Verbose | Get-NetDomainTrust

Get-ADTrust -Filter 'msDS-TrustForestTrustInfo -ne "$null"'
</code></pre>





## 🔫User Hunting

**❗ Find machines where the current user can PSRemote into as local admin**

```powershell
. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess

winrs -r:hostnamee cmd
Enter-PSSession -ComputerName hostname.fqdn.local

. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
Find-WMILocalAdminAccess - Computerfile computer.txt -verbose (all domain Computerhostnames from Get-NetComputer)
winrs -r:hostname cmd
Enter-PSSession -ComputerName hostname.fqdn.local
```



**❗Find all machines on the current domain where the current user has local admin access / Contacting not only DC (noisy...)**&#x20;

{% code overflow="wrap" %}
```powershell
Find-DomainUserLocation -verbose
Find-LocalAdminAccess -Verbose  ==> Results weird?!?!
```
{% endcode %}

{% hint style="info" %}
This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Invoke-CheckLocalAdminAccess on each of those machines. Since this function is extremely noisy and can cause a network spike, it is better to run it in chunks of machines (using the option -ComputerFile) rather than all machines at once. The function leaves a 4624 (logon event) or 4634 (logoff event) for each machine on the domain.

This same function can also be done with the help of remote administration tools like WMI and powershell remoting. It is pretty useful in cases where ports of RPC and SMB (which are used by Find-LocalAdminAccess) are blocked. In such cases, you can use an alternate tool --> Find-WMILocalAdminAccess.ps1 (this is because, WMI by-default requires local admin access)
{% endhint %}

**Find local admins on all machines of the domain (needs admin privs on non-dc machines)**

```powershell
Invoke-EnumerateLocalAdmin -Verbose
```

{% hint style="info" %}
This function queries the DC of the current or provided domain for a list of computers (Get-NetComputer) and then use multi-threaded Get-NetLocalGroup on each machine.
{% endhint %}

**❗Find computers where a specified user/group (domain admins or RDPusers or etc.) has sessions (by-default Domain admins group) - and we have local admin on that machine**

<pre class="language-powershell"><code class="lang-powershell">Find-DomainUserLocation -verbose
Find-DomainUserLocation -verbose -usergroupidentity "RDPUsers" -checkaccess

<strong>Invoke-UserHunter -Verbose
</strong>Invoke-UserHunter -CheckAccess  //check if we have local admin on target
Invoke-UserHunter -GroupName "RDPUsers"
</code></pre>

{% hint style="info" %}
This function queries the DC of the current or provided domain for members of the given group (Domain admins by default) using Get-NetGroupMember, gets a list of computers (Get-NetComputer) and list sessions and logged on users (Get-NetSession / Get-NetLoggedon) from each machine
{% endhint %}

**❗To find where our current user has local admin privs on servers that have domain admin sessions** &#x20;

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-UserHunter -CheckAccess
<strong>Find-DomainUserLocation -CheckAccess    // PowerView Dev!! doesn't check if we have access?
</strong><strong>
</strong></code></pre>

**Find computers (high value targets only) where a domain admin is logged-in**

```powershell
Find-DomainUserLocation -Stealth
Invoke-UserHunter -Stealth 
```

{% hint style="info" %}
This function queries the DC of the current or provided domain for members of the given group (Domain admins by default) using Get-NetGroupMember, gets a list of **only high value targets** (high traffic servers) - DC, File servers & distributed file servers, for being stealthy and generating lesser traffic and lists sessions and logged on users (Get-NetSession / Get-NetLoggedon) from each machine
{% endhint %}

**❗Query on the specified host for 100 seconds for any sessions for the user called "administrator"**&#x20;

{% code overflow="wrap" %}
```powershell
Invoke-UserHunter -Computername hostname -poll 100 -username administrator -delay 5 -verbose 
```
{% endcode %}

**Manually get Sessions of a Computer**

```powershell
Get-NetSession -Computername hostname.local 
```



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









