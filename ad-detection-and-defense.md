# AD - Detection and Defense

## General

* Dont allow or limit of DA to other machines - only to DC
* Never run a service with DA!
  * Credential Guard, Protected User Group and protected process lsass protection is rendered useless if a service runs as DA. Because for services the secrets are stored in the lsasecret: [https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/](https://devblogs.microsoft.com/scripting/use-powershell-to-decrypt-lsa-secrets-from-the-registry/)
* Check out Temporary Group Membership (Requires Privileged Access Management Feature to be enabled which cant be turned off later) - Allow DA for only 20 minutes

<pre data-overflow="wrap"><code><strong>Add-ADGroupMember -Identity 'Domain Admins' -Member newDAUsername -MemberTimetoLive (New-TimeSpan -minutes 20)
</strong></code></pre>

## **Golden Ticket**

4624 Account logon\
4672 Admin logon / this will be generated on to the domain controller itself

{% code overflow="wrap" %}
```powershell
Get-WinEvent -FilterHashtable @{Logname='Securtiy';ID=4672} -MaxEvents 1 | fl -property *
```
{% endcode %}

## Silver Ticket

4624 Account logon\
4634 Account logoff\
4672 Admin logon / only shows up if silver ticket is used against DC

❓All three for all admin logons, right?

## Skeleton Key

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

## **DSRM / Malicious SSP**

4657 - Audit creation/changes of HLKM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior

4657 - Audit creation/changes of \
HLKM:\System\CurrentControlSet\Control\Lsa\SecurityPackages

## **Kerberoast**

Really silent attack\
4769 - Kerberos Ticket was requests / a lot of these events - maybe we filter more\
\- Service name should not be krbtgt\
\- Servce name does not end with $ (filters out machine accounts for services)\
\- Accoutn names should not be machine@domain (filter out requests from machines)\
\- Failure Code is '0x0' (to filter out failures)\
\- Ticket encryption type is 0x17, which is important\
Starting with Server 2008 they use AES, which is 0x12\


* Service Accounts Passwords should be hard to guess (>25 chars)
* Use Managed Service Accounts (Automatic PW change periodically and delegated SPN Management)\
  [https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831782(v=ws.11)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831782\(v=ws.11\))

![](<.gitbook/assets/image (5) (3).png>)

## **(Un-)Constrained Delegation**

* Limit DA/Admin Logins to specific server e.g DC
* Set "Account is sensitive and cannot be delegated" for privileged Accounts\
  [https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts](https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts)

## ACL Attacks

Audit Policy must be enabled for the folloing EventID, which are relevant\
4662 - An Operation was performed on a object\
5136 - A directory serivce object was modified\
4670 - Permissions on a object was changed

Tool: AD ACL Scanner - Lets you create and compare reports of ACLs\
[https://github.com/canix1/ADACLScanner](https://github.com/canix1/ADACLScanner)

## Trust Ticket / Inter Forest Attack

A child domain compromise we have to assume forest compromise. With cross-forest attacks we have some defenses!

**SID Filtering**

* Avoid Attacks which abuse SID history attribte accross forest trust
* Enabled by default on all inter-forest trusts\
  Micosoft considers forest an not the domain to be the secuity boundary
* SID filtering can break applications and user access => it si therefore often disabled
* ❓ Enterprise Domain Controllers Group are excluded from SID filtering => Use that in attacks?

**Selective Authentication**

* In inter-forest trust, if selective authentication is enabled, users between the trusts will not automatically authenticated. Individual access per user need to be given.

## Microsoft ATA (Advanced Threat Analytics)

* Traffic to DC is mirrored to ATA and good behaviour is "learned"
* Can detect behavior anomalies
* A ATA Lightweight Gateway is available, which can be installed on the DC - no big architecutre
* 90 day free trial
* ATA can detect:

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

Silver Tickets?

{% embed url="https://learn.microsoft.com/en-us/advanced-threat-analytics/what-is-ata" %}

**Bypass Enumeration**\
****Invoke-UserHunter -verbose  //exclude the DC host itself! It is pointless, because Domain Admin is ok to be logged on\
\
Get-NetComputer => Save to file and delete DCs\
Invoke-UserHunter -computerfile savedfile.txt

**Bypass Over-Pass-The-Hash Attack**

Encryption method\
****![](<.gitbook/assets/image (8).png>)

**Bypass Golden Ticket**&#x20;

Use, NTLM, AES128, AES256 inn all requests\
![](<.gitbook/assets/image (1) (1).png>)\
&#x20;\


## Architectural Cahnges

### LAPS

* Computer objects get two new attrbributes\
  ms-mcs-AdmPwd - clear text pw\
  &#x20; \=> can be viewed if permissions wrong or we have enough permissions\
  ms-mcs-AdmPwdExpirationTime - controls the pw change\
  &#x20; \=> can be abused, that the local password will never expire, if we can write that attribute
* Passwords are stored in Cleartext on DCs and transmitted encrypted
* Enumeration it is possible to get what users can access the cleartext pw => new targets
* Attack of the admpwd.dll on the local machine?\
  [https://www.hackingarticles.in/credential-dumpinglaps/  \
  https://adsecurity.org/?p=3164  \
  https://www.adamcouch.co.uk/laps-ms-mcs-admpwd-enumeration-attack-vector/\
  ](https://www.hackingarticles.in/credential-dumpinglaps/https://adsecurity.org/?p=3164https://www.adamcouch.co.uk/laps-ms-mcs-admpwd-enumeration-attack-vector/)

### Credential Guard

* Uses virtualization based security to isolate secrets
* Effective on stopping PTH and Over-PTH attacks by restricting access to NTLM hashes and TGTs. Starting W10 1709 it is not possible to write Kerberos tickets to memory even if we have credentials
* Credential Guard only protects the lsass process. Credentials for local account in SAM and Service account credentials from LSA secrets are not protected
* Credential Guard can not be enabled on DC
* It has been proved possible to replay service accounts credentials for lateral movement even if credential guard is enabled

### Device Guard

Three primary components

* Confiurabel Code Integrity (CCI) - Let only trusted code run
* Virtual Secure Mode Protected Code Integritiy - Enforce CCI with kernel mode (KMCI) and usermode (UMCI)
* Platform and UEFI Secure Boot - Ensure boot binaries and firmware integrity
* UMCI is something which interfecs with most lateral movment attacks
* Bypasses exist like using whitelisted, signed applications such as csc.exe, MSBuild.exe, mshta.exe etc.



## Protected User Group

* Intorduced in Server 2012 R2
* Needs all DC to be Server 2008 or later
* Not recommended by MS to add DA and EA to this group, without testing the impact of lock out
* No offline logon for the users
* Having computer and service accounts in this group is useles - their credentials will always be present on the host machine - LSA secret
* Users added to this group\
  \- Cannot use CredSSP and WDigest => means no more cleartext credentials caching\
  \- NTLM is not cached\
  \- Kerberos does not use DES or RC4 keys. No caching of clear text creds or logn term keys
* If the domain functional level is Server 2012 R2, the following points are also enforced per User\
  \- No NTLM authentication\
  \- No DES or RC4 key in Kerberos pre-auth\
  \- No constrained or unconstrained delegation\
  \- No renewal of TGT beyond initial four hour lifetime - Hardcoded and unconfigurable "Maximum lifetime for user ticket" and "Maximum lifetime for user ticket renewal"

## Privileged Administrative Workstaions (PAWs)

* A hardened workstation / Jumphost
* Can provide protection from phishing attacks, OS Vulns, credential replay attacks
* Seperate Workstation/VM for regular work and admin work / or a VM on a PAW for User tasks
* Shared Jump-Hosts should not be used or only with high care! E.g credential caching of a lot of admins etc.

## Active Directory Administrative Tier Model

Tier 0 - Accounts, Groups, Computer accross the enterprise like dc, da, ea

Tier 1 - Accounts, Groups, Computers which have access to resoruces having significatn amount of business value e.g. Application Server Admin, OS Administrators, Hypervisor Plattform

Tier 2 - Administrative accounts user workstation/devices. Helpdesk, Support etc. which can impact a lot of users

* Control Restrictions: What admins Control

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

* Logon  Restriction: Where admins can log-on to

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

Tier 1 => Tier 0 access should be really restricted and really role-based etc!

## Enhanced Security Admin Environment (ESAE)
