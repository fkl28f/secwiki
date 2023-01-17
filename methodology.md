# Methodology

## New User

\=> New Bloodhound

Enumerate where you have local admin with the new user

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

Enumerate Sessions with the new privs, because you need to be local admin&#x20;

```powershell
Invoke-Userhunter -groupname "domain admins"
```

Find modifieable ACLs with user / Member Groups

{% code overflow="wrap" %}
```powershell
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "yourusername"}
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "GroupName"}
```
{% endcode %}



### New Computer



\
