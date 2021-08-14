---
title: Reconaissance - External
description: 
published: true
date: 2021-08-14T08:33:51.278Z
tags: security, reconaissance, external
editor: markdown
dateCreated: 2021-08-09T14:39:13.316Z
---

# Reconaissance - External
## Extract Metadata
Downlod files:
metagoofil -d [targetDomain.com] -l 100 -n 100 -t doc,docx,xls,xlsx,pdf -w -o metagoofil_results -f

Search for intertesting metadata:
exiftool -r *.pdf | egrep -i "Author|Creator|Email|Proucer|Template" | sort -u

Robots.txt

.htaccess

## SSL / TLS & Security Headers / Certificates
https://www.ssllabs.com/
https://securityheaders.com/
https://crt.sh
	
Whois

ASN Info
https://bgp.he.net/
https://www.ultratools.com/tools/asnInfo
https://ipinfo.io/ 
https://ipdata.co/
https://ipinfo.io/AS34125
whois -h whois.radb.net -- '-i origin AS21161' | grep -Eo "([0-9.]+){4}/[0-9]+" | head


## DNS
https://dnsdumpster.com/
https://www.robtex.com/

	dnsrecon -d [target.dom]
	dnsrecon -d [target.dom] -s -g -b -k -w -z
	dnsenum --enum [target.dom]
	fierce --domain [target.dom]

	All records
		dig +nocmd [target.dom] any +noall +answer
	
	Auth. Nameserver
		dig +short [target.dom]
	
	All records
		dig +nocmd [target.dom] any +noall +answer
	
	NS records
		dig +nocmd [target.dom] ns +noall +answer
		
	TXT Records
		dig +nocmd [target.dom] txt +noall +answer
	A records
		dig +nocmd [target.dom] a +noall +answer
	PTR records
		dig +nocmd [target.dom] ptr +noall +answer
	SOA records
		dig +nocmd [target.dom] soa +noall +answer
	
	MX records
		dig +nocmd [target.dom] mx +noall +answer
	
	Zonetransfer (AXFR) - failed
		dig +short [target.dom]
		dig axfr [target.dom] [target-DNSServer-IP]

Specific nameserver:
dig linux.org @8.8.8.8

# Nmap
Full TCP Syn Scan / all Ports / Enum everything
nmap -vv -sS -Pn -p0- -A

TCP Syn Scan / cetain ports
nmap -vv -sS -Pn -p 1-500 127.0.0.1

UDP Scan only on port 53
nmap -vv -sU -Pn -p 53 127.0.0.1

-A - Combines -O -sC -sV
-O - OS Enum
-sC - Script Scanning
-sV - Version Scanning
-T4 - Scan faster, more drops
-oA - Output in all three formats

### Test Scan Hosts
scanme.nmap.org

## Google Dorks
Use "inurl" and "filetype"

## Joomla / Wordpress / Typo3
https://hackertarget.com/
https://sitecheck.sucuri.net/
https://www.shodan.io/

Joomscan -u [target.dom]

Typo3 Scan
https://github.com/whoot/Typo3Scan

Whatweb -v [target.dom]

## Mail
Mail relay
	telnet mail.[target.dom] 25
	HELO secwiki.ch
	MAIL FROM: <test@[sender.dom]>
	RCPT TO: <test2@[target.com]>
[Enter] [Enter]