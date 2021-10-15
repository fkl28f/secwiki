---
title: Windows Hardening
description: 
published: true
date: 2021-08-10T07:11:27.061Z
tags: security, pentesting, windows, hardening
editor: markdown
dateCreated: 2021-08-09T14:24:57.720Z
---

# Windows Client Hardening	
## Privileged Account on Client
- Privileged Account (domain admin, enterprise admin, exchange admin) should not be allowed to connect via RDP to Cleints Client
-		Deny log on through Remote Desktop Services
- 	Computerkonfiguration/Windows-Einstellungen/Sicherheitseinstellungen/Lokale Richtlinien/Zuweisung von Benutzerrechten/Anmeldung über Remotedesktopdienste verweigern => 
-		Nichts konfiguriert - Hier sollten alle Domain Admins, Exchange admin, enterprise admin drin sein
		• Cached credentials
			§ HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\Current Version\Winlogon\
			§ Value name: CachedLogonsCount
			§ Values:0-50 / 0 ist deaktiviert



## Cached credentials GPO
- GPO Computerkonfiguration/Window-Einstellungen/Sicherheitseinstellungen/Lokale-Richtlinien/Sicherheitsoptionen/ Interaktive Anmeldung: Anzahl zwischenzuspeichernder vorheriger Anmeldungen
- Registry Computer\HKEY_LOCAL_MACHINE\SECURITY\Cach


## RDP Hardening
 Computer/Administrative Vorlagen/System/Delegierung von Anmeldeinformationen
 
 		This policy setting applies to applications using the CredSSP component (for example: Remote Desktop Connection).
		
		Some versions of the CredSSP protocol are vulnerable to an encryption oracle attack against the client.  This policy controls compatibility with vulnerable clients and servers.  This policy allows you to set the level of protection desired for the encryption oracle vulnerability.
		
		If you enable this policy setting, CredSSP version support will be selected based on the following options:
		
		Force Updated Clients: Client applications which use CredSSP will not be able to fall back to the insecure versions and services using CredSSP will not accept unpatched clients. Note: this setting should not be deployed until all remote hosts support the newest version.
		
		Mitigated: Client applications which use CredSSP will not be able to fall back to the insecure version but services using CredSSP will accept unpatched clients. See the link below for important information about the risk posed by remaining unpatched clients.
		
		Vulnerable: Client applications which use CredSSP will expose the remote servers to attacks by supporting fall back to the insecure versions and services using CredSSP will accept unpatched clients.
		
		For more information about the vulnerability and servicing requirements for protection, see https://go.microsoft.com/fwlink/?linkid=866660
