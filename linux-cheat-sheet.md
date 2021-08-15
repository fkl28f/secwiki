---
title: Linux Cheat Sheet
description: 
published: true
date: 2021-08-15T17:29:49.311Z
tags: linux, cheatsheet, sn
editor: markdown
dateCreated: 2021-08-05T21:51:52.843Z
---

# Linux Cheat Sheet
## KeePassXC with Copy/Paste Support
Run from shell: QT_QPA_PLATFORM=xcb keepassxc

## View Devices/Disks/Volumes
df -h
fdisk -l


## Write/Read File or Image with DD

### Write USB Stick to an Image 
sudo dd if=/dev/sdb of=~/USB_image

### Write an Image to a USB stick: 
sudo dd if=~/USB_image of=/dev/sdb status=progress conv=fdatasync

sudo dd if=/home/ak/Documents/Temp_NoBackup/MemoryStick/Mem8gb of=/dev/sdb status=progress conv=fdatasync

## Format USB Stick with multiple OS (Windows & Fedora) Partitions

https://askubuntu.com/questions/423300/live-usb-on-a-2-partition-usb-drive
Use gparted!!


 1. Created a new 10 GB, ntfs, logical partition, with 25 MB Free space preceding, has to be the first otherwise Windows will not recognise it
    and 0 MB following, labeled Storage (must be first on the drive)
 2. Created a new 5 GB, fat32, logical partition, with 0 MB preceding and following
 3. Set a boot flag for the second partition -> Use Unetbootin to write ISO to this partiation
 4. (Created the other partitions which are not needed)
 5. Booted to a Ubuntu Live Session loaded on a DVD and selected Try Ubuntu 
    without installing from the gRUB menu
 6. Opened Startup Disk Creator with the USB flash drive pluged-in
 7. The Ubuntu-Desktop 12.04 Image and pny USB 2.0 flash drive (/dev/sdh2) 5.0 GB 
    partition were already selected, moved the How much slide to store documents 
    and settings in reserved extra space and selected Make Startup Disk


## VM & USB devices

### Use USB device in Windows VM
sudo systemctl stop usbmuxd
sudo systemctl disable usbmuxd

### Convert .ova to .qcow2:
tar -xfv name.ova
qemu-img convert -O qcow2 file.vmdk new_file.qcow2

### Compress .qcow2 Files
qemu-img convert -O qcow2 source.qcow2 shrunk.qcow2     //removes sparse space, Disk speed will not decrease
qemu-img convert -c -O qcow2 source.qcow2 shrunk.qcow2  //removes sparse space and compress, Warning: Disk speed will decrease but smaller .qcow2 File

### Internet with VPN
On QEMU level: New virtual network; Physical device tun0; mode:NAT
On VM level: NAT to tun0

## SD-Cards Format & Image write

sudo dd if=raspbx-04-04-2018.img of=/dev/mmcblk0 bs=1M status=progress conv=fdatasync

## Write ISO to USB Stick

sudo dd if=fedora30.iso of=/dev/xyz bs=4M status=progress conv=fdatasync


## Searching & Finding big files

### search the 10 biggest fiels/folders: 
sudo du -a / | sort -n -r | head -n 10

### Search for folders with a lot of files/inodes
du --inodes -S -xS | sort -rh | sed -n '1,50{/^.\{71\}/s/^\(.\{30\}\).*\(.\{37\}\)$/\1...\2/;p}'
find /path_to_search/ -xdev -printf '%h\n' | sort | uniq -c | sort -k 1 -n

### Find the files with the followingin the filename:
find . -print | grep bouncy*
find . -iname "*jks*"   //case-insensitive
find . -name "*jks*"   //case-sensitive

### Find files with the content
grep -ri "word" .    // case-insensitve
grep -r "word" .    // case-nsensitve
grep -rl "foo" *    The following will instead only output only filename, without the matching line


## Backup / Sync Files
**Syncs all files and deletes deleted folder/files in source / Syncs also if files already exist**
rsync -avh --progress --delete "/path/to/source" "/path/to/destination"

**Syncs all files and deletes deleted folder/files in source / Sync only the files which are not yet present in target**
rsync -tvhr -P --delete "/source/folder "/destination/folder"

> --dry-run
> --ignore-existing  -  skip updating files that exist on receiver
> --update - This forces rsync to skip any files which exist on the destination and have a modified time that is newer than the source file. (If an existing destination file has a modification time equal to the source file's, it will be updated if the sizes are different.)
{.is-info}




## Docker

See configuration: 
docker inspect [containerName/ID]
docker container ls
docker ps
docker start [containerName/ID]
docker stop [containerName/ID]
docker log [containerName/ID]
Config file:
/var/lib/docker/containers/container-id/config.v2.json 



## Startup Commands / Startp Script/Application when System is started/rebootet

Run a script under the user:
1. Create .sh file
2. chmod +x filename.sh
3. crontab -e
4. Enter the following: @reboot (sleep 90 ; sh /location/script.sh)


## SSH with predefined Hosts and configurations

vi .ssh/config

Host *
 ServerAliveInterval 60

Host vps
 HostName IP_Addr
 User username
 Port port

## Networking

ss -tulpen
netstat -tulpen
systemctl status sshd
systemctl restart sshd


## Backup + Merge KeePass

keepassxc-cli merge primary_synced_into.kdbx Source_dom6-8.kdbx

sudo rsync -avh --progress /media/veracrypt6/ /media/veracrypt7/


## Delete a file securely
shred -v -n 25 -u -z file_you_wanna_shred


## Bash tipps
vi .bashrc / add: alias ll='ls -alh --color=auto'
last reboot
journalctl -xe  //systemd log

firefox -P   //Manage profiles; location firefox profiles: /home/ak/.mozilla/firefox/


## Cron / Jobs
cd /var/log/
cat cron | grep yum-daily
cat yum.log | grep Updated

crontab -e
15 4 * * * /usr/sbin/reboot   // Restart every day at 04:15
crontab -l

https://crontab.guru
- or - 
Write directly to /etc/crontab schreiben


## Unattended update/upgrade / Ubuntu 20.04 TLS
sudo timedatectl set-timezone Europe/Zurich
sudo apt update && sudo apt upgrade
sudo apt install unattended-upgrades apt-listchanges
sudo dpkg-reconfigure -plow unattended-upgrades
sudo vi /etc/apt/apt.conf.d/50unattended-upgrades
	Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
	Unattended-Upgrade::Remove-Unused-Dependencies "true";
	Unattended-Upgrade::Automatic-Reboot "true";
	Unattended-Upgrade::Automatic-Reboot-Time "22:00";

sudo nano /etc/apt/apt.conf.d/20auto-upgrades
	APT::Periodic::Update-Package-Lists "1";
	APT::Periodic::Download-Upgradeable-Packages "1";
	APT::Periodic::AutocleanInterval "7";
	APT::Periodic::Unattended-Upgrade "1";

sudo unattended-upgrades --dry-run

cat /var/log/unattended-upgrades/unattended-upgrades.log

Link
https://www.linuxbabe.com/ubuntu/automatic-security-update-unattended-upgrades-ubuntu
