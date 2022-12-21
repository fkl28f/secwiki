# Bloodhound/Sharphound Basics

## **Neo4j**

neo4j.bat install-service\
neo4j.bat start

neo4j:neo4j

## **Bloodhound**

**Start**\
****. .\SharpHound.ps1

**Collect all domain data**\
Invoke-BloodHound -CollectionMethod All -Verbose

**Collect all domain data but stealthier**\
Invoke-BloodHound -CollectionMethod All -ExcludeDC

**Collect the session details of the domain users as well**\
Invoke-BloodHound -CollectionMethod LoggedOn -Verbose

**Python Bloodhound**\
[https://github.com/fox-it/BloodHound.py](https://github.com/fox-it/BloodHound.py)\
pip install bloodhound

\--collectionmethod All

bloodhound-python -u support -p 'securePW' -ns 10.10.10.192 -d blackfield.local -c all

If you are running it through proxychains add `--dns-tcp` for the DNS resolution to work throught the proxy.

## Sharphound&#x20;

SharpHound.exe -c All -s\
SharpHound.exe -c SessionLoop -s\
SharpHound.exe --CollectionMethod All --LdapUsername \[username] --LdapPassword \[pw]



\
**Tricks within Bloodhound**

* Custom Queries
  * [https://github.com/CompassSecurity/BloodHoundQueries](https://github.com/CompassSecurity/BloodHoundQueries)
  * [https://github.com/hausec/Bloodhound-Custom-Queries](https://github.com/hausec/Bloodhound-Custom-Queries)
* Right click on a group node "Expand"
* Ctrl Key - turn on/off node labels
*

## Detection

Event ID 4624, 4634 from a single machine in a short periode of time accross a lot of computers in the Domain.

