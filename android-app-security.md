---
title: Android App Security
description: 
published: true
date: 2021-08-06T21:19:34.484Z
tags: security, android
editor: markdown
dateCreated: 2021-08-06T21:00:45.191Z
---

# Android App Security

## adb / Interacting with Smartphone
adb Location: C:\Users\[]\AppData\Local\Android\Sdk\platform-tools

- Check connected devices
`adb devices`

- Show all installed packages
`adb shell pm list packages`

- Show only user installed packages:
`adb shell pm list packages -3"|cut -f 2 -d ":`

- Get the full path/name of app
`adb shell pm path com.example.someapp`
- Pull app to windows / output to current directory
`adb pull /data/app/com.example.someapp-2.apk`

- Pull anything something from Smartphone to Windows
`adb pull /sdcard/video.mp4 C:\Users\Jonathan\Desktop`

- Install APK on phone
`adb install "C:\Users\PatchMe.apk"`

- Push Files from Notebook to Smartphone
`adb devices`
`adb push files-to-push-from-notebook-to-smartphone.txt /full/path/on/android/`
`adb push files-to-push-from-notebook-to-smartphone.txt /storage/emulated/0/temp`

## Reverse/Decode .apk
- Rename .apk to zip and unpack => brings classes.dex
- DEX2JAR 
		`./d2j-dex2jar.sh ../example.apk/classes.dex -o output_file.jar`` => On classes.dex
		./d2j-dex2jar.sh ../example.apk -o output_file.jar` => On .apk

- Unpack .apk files & geenrate Smali
		$ java -jar apktool_2.1.1.jar d example.apk 

## Build & sign APK
1. Build
apktool b folder_with_all_files
Cd [dist]   ==> here is apk
Important: You have to decompile with apktool first in order to work with the build. If you do the renaming apk to .zip it is not working!!

2. Sign the .apk
Variant1: Install "apk-signer" app on phone and sign with this app the .apk

Variant 2:  cd "C:\Program Files\Android\Android Studio\jre\bin"
Create a file called eToken.cfg with the content:
name=eToken
library=C:\Windows\System32\eTPKCS11.dll
=> Place the file in C:\Program Files\Android\Android Studio\jre\bin

keytool -genkey -alias alias_ak -keystore keystore_ak
keytool -importkeystore -srckeystore keystore_ak -destkeystore keystore_ak -deststoretype pkcs12
jarsigner -keystore keystore_ak "C:\Program Files\Android\Android Studio\jre\bin\PatchMe_patchedAK.apk" alias_ak
Adb ubstakk "path_to\PatchMe_patchedAK.apk"
Check phone because of security pop ups

## Reverse Obfuscation
http://apk-deguard.com/
https://github.com/Gyoonus/deoptfuscator

## Certificate Pinning
https://github.com/51j0/Android-CertKiller

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


## Search for Strings
hash
md5
sha
SecretKey
crypto
key
Credential 
setPassword
encrypt
security
signature
key_algorithm
algorithm
block_mode
auth_
auth_biometric
security_level
encrypt_mode
android.security
keyStore.setEntry
setKeyEntry
setEntry
MD5
SHA
AES
ChaCha
keyStore
key
API
API_Key
sentry
