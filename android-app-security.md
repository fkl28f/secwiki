---
title: Android App Security
description: 
published: true
date: 2021-08-06T21:28:01.481Z
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
- https://github.com/51j0/Android-CertKiller

- Add your own CA / Configure a custom CA
https://developer.android.com/training/articles/security-config

- Configure CA in Debugging Mode

https://developer.android.com/training/articles/security-config

- Possible Downgrade to API 23 or lower

- As Steffen said you might need to patch the app to disable certificate pinning. Most mobile apps don't use it though :) Thus you just need to enable SSL connections with self-signed certificate. To allow that with Android application do following:
	• Download apktool from https://ibotpeaches.github.io/Apktool/
	• Unpack apk file (according to apktool 2.4.1): java -jar apktool.jar d app.apk
	• Modify AndroidManifest.xml by adding android:networkSecurityConfig="@xml/network_security_config" attribute to application element.
	• Create file /res/xml/network_security_config.xml with following content:
`<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>`
	• Build patched apk: java -jar apktool.jar b app -o app_patched.apk
	• Generate keys to sign apk: keytool -genkey -alias keys -keystore keys
	• Sign apk file: jarsigner -verbose -keystore keys app_patched.apk keys
	• If necessary convert apk to jar for further analysis: d2j-dex2jar.sh app.apk
More information: https://developer.android.com/training/articles/security-config
<https://stackoverflow.com/questions/52862256/charles-proxy-for-mobile-apps-that-use-ssl-pinning> 

- A major change in Android's network security is that from Android 7.0 onwards user installed certificate authorities and
those installed through Device Admin APIs are no longer trusted by default for apps targeting API Level 24+. This means that you may not be able to capture network traffic deriving from applications targeting API Level 24+, even with your proxy's certificate successfully installed in your device.
To overcome this obstacle you will have to leverage another change in Android's network security, called Network Security
Config (https://developer.android.com/training/articles/security-config.html)
 As Google states Network Security Config lets apps customize their network security settings in a safe, declarative configuration file without modifying app code. Using this configuration file you can trust a custom set of Cas instead of the platform default.

So in order to be able to capture traffic deriving from applications targeting API Level 24+, you should do thefollowing:
• Decode the application using apktool
• Introduce a network_security_config.xml file at res/xml folder of the application
• Add the self signed or non public CA certificate, in PEM or DER format, to res/raw/ name_of_your_choice folder of the
application
• Repackage and sign the application

Some Apps may ignore the system wide proxy. Then it is necessary to root the device and use ProxyDroid or launching an emulator usint the -http-proxy line option


## Extract Remote Certificate / Change Certificate Pinning
`echo -n | openssl s_client -connect www.elearnsecurity.com:443 | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /tmp/els.cert`

Verify if the pulbic key matches the one includes in the appliacations Android Studio project
https://github.com/moxie0/AndroidPinning
Python pin.py /tmp/els.cert

Change the value of the pins String array and try to connect

Learn about certificate pinning / adding certificate to keystore in the app etc:
https://github.com/ikust/hello-pinnedcerts


## Static/Dynamic Code Analysis Tools

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


## Open .apk in Android Studio
In Android studio: Build/Analyze APK


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

## Android Screen Mirroring/Sharing to Windows 10/Linux/OSX
https://github.com/Genymobile/scrcpy

Android connecten via USB
Developer mode & Debug mode ON

## Online Tools for Analysis
https://www.immuniweb.com/mobile/
https://report.ostorlab.co/
https://amaaas.com/
https://undroid.av-comparatives.info/analysis.php