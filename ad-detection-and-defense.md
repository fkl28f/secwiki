# AD - Detection and Defense

## General

* Dont allow or limit of DA to other machines - only to DC
* Never run a service with DA!
  * Credential Guard, Protected User Group and protected process lsass protection is rendered useless if a service runs as DA. Because for services the secrets are stored in the lsasecret: [https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/](https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/)
* Check out Temporary Group Membership (Requires Privileged Access Management Feature to be enabled which cant be turned off later) - Allow DA for only 20 minutes

<pre data-overflow="wrap"><code><strong>Add-ADGroupMember -Identity 'Domain Admins' -Member newDAUsername -MemberTimetoLive (New-TimeSpan -minutes 20)
</strong></code></pre>

## Important EventID

### **Golden Ticket**

4624 Account logon\
4672 Admin logon / this will be generated on to the domain controller itself

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{Logname='Securtiy';ID=4672} -MaxEvents 1 | fl -property *
```
{% endcode %}

### Silver Ticket

4624 Account logon\
4634 Account logoff\
4672 Admin logon / only shows up if silver ticket is used against DC

### Skeleton Key

7045 System Event ID - A service was installed on the system (Type Kernel Mode driver)\
\
If "Audit privilege use" are enabled:\
4673 Security Event ID - Sensitive Privilege Use\
4611 - A trusted logon process has been registered with the Local Security Authority

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{Logname='Securtiy';ID=7045} | ?{$_.message -like "*Kernel Mode Driver*"}
```
{% endcode %}

Mitigation Skeleton key & other:\
\- Run lsass as a protected process or as a protected process light => This forces attackers to load a kernel mode driver. Maybe some drivers/plugin wont work, test it

{% code overflow="wrap" %}
```powershell
New-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -name RunAsPPL -Value 1 -Verbose
Verify after a reboot
Get-WinEvent -FilterHashtable @{Logname='System';ID=12'} | ?{$_.message like "*protected process*"}
```
{% endcode %}

\


