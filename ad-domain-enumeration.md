# AD - Domain Enumeration

Enumeration can be done by using Native executables, WMI and .NET classes.

**Basic Info of Domain (Forest/Domain Name, Domain Function Level etc.)**

$ADClass=\[System.DirectoryServices.ActiveDirectory.Domain]\
$ADclass::GetCurrentDomain()

**Tools**

* PowerView
* _Active Directory PowerShell Module_
  * Without RSAT and without local Admin is possible
  * Works fine with Constrained Language Mode
  * Microsoft Signed - low detection

**Get Current Domain**\
Get-NetDomain\
_Get-ADDomain_

**Get Object of another domain**\
Get-NetDomain -domain dom.local\
_Get-ADDomain -identity dom.local_

**Get domain SID for the corrent domain**\
Get-DomainSID\
_(Get-ADDomain).Domain.SID_



__

__
