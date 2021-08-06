---
title: Android App Security
description: 
published: true
date: 2021-08-06T21:00:59.346Z
tags: security, android
editor: markdown
dateCreated: 2021-08-06T21:00:45.191Z
---

# Android App Security


## Extract Remote Certificate / Change Certificate Pinning
`echo -n | openssl s_client -connect www.elearnsecurity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /tmp/els.cert`

Verify if the pulbic key matches the one includes in the appliacations Android Studio project
https://github.com/moxie0/AndroidPinning
Python pin.py /tmp/els.cert

Change the value of the pins String array and try to connect

Learn about certificate pinning / adding certificate to keystore in the app etc:
https://github.com/ikust/hello-pinnedcerts


## Static Code Analysis Tools / Websites

### MobFS
https://github.com/MobSF/Mobile-Security-Framework-MobSF
https://mobsf.github.io/docs/#/

Setup MobFS:
`docker pull opensecurity/mobile-security-framework-mobsf`
`docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest`

### QARK
Install QARK on Kali:
`pip install --user qark`
https://github.com/linkedin/qark/

Use QARK:
`cd /home/()/.local/bin`
`./qark --apk /home/()/Documents/MAPST/com.[name]/com.[name].apk`
