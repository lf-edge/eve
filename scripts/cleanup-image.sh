#!/bin/bash

echo "Removing files and directories from the image mounted at `pwd`"
echo; read -n 1 -s -p "Are you sure? ^C to abort"; echo; echo

if [ ! -f etc/wpa_supplicant/wpa_supplicant.conf.zededa ]; then
    echo "No etc/wpa_supplicant/wpa_supplicant.conf.zededa - wrong directory?"
    exit 1
fi

# Remove any additional WiFi passwords
cp -p etc/wpa_supplicant/wpa_supplicant.conf.zededa etc/wpa_supplicant/wpa_supplicant.conf

# Restore /etc/hostname to not be the uuid
echo ubuntu >etc/hostname

# /opt/zededa/etc/ should just have
# onboard.cert.pem onboard.key.pem
# lisp.config.base  root-certificate.pem  server

rm opt/zededa/etc/{device.cert.pem,device.key.pem,hwstatus.json,swstatus.json,uuid,zedrouterconfig.json,zedserverconfig,network.config.global}

echo "Remaining files in opt/zededa/etc:"
ls opt/zededa/etc

rm -rf var/run/zedmanager
rm -rf var/run/zedrouter
rm -rf var/run/domainmgr
rm -rf var/run/identitymgr
rm -rf var/run/downloader
rm -rf var/run/verifier

# Preserve var/tmp/zedmanager/downloads
echo "Existing items in var/tmp/zedmanager/downloads"
du -sm var/tmp/zedmanager/downloads
ls var/tmp/zedmanager/downloads/*

rm -rf var/tmp/zedmanager/config/*
rm -rf var/tmp/zedrouter/config/*
rm -rf var/tmp/domainmgr/config/*
rm -rf var/tmp/identitymgr/config/*
rm -rf var/tmp/downloader/config/*
rm -rf var/tmp/verifier/config/*

rm -rf var/log/zedmanager*
rm -rf var/log/zedrouter*
rm -rf var/log/domainmgr*
rm -rf var/log/identitymgr*
rm -rf var/log/downloader*
rm -rf var/log/verifier*
rm -rf var/log/eidregister*
rm -rf var/log/xen/*

rm -rf opt/zededa/lisp/logs/*
rm -rf opt/zededa/lisp/logs.*

echo "Removing ssh identity"
rm -f etc/ssh/ssh_host_*
grep -q "dpkg-reconfigure openssh-server" etc/rc.local
if [ $? != 0 ]; then
    echo "You need to manually setup rc.local for ssh-keygen. Add:"
    echo "test -f /etc/ssh/ssh_host_dsa_key || dpkg-reconfigure openssh-server"
fi
