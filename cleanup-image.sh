#!/bin/bash

echo "Removing files and directories from the image mounted at `pwd`"
echo; read -n 1 -s -p "Are you sure? ^C to abort"; echo; echo

if [ ! -f etc/wpa_supplicant/wpa_supplicant.conf.zededa ]; then
    echo "No etc/wpa_supplicant/wpa_supplicant.conf.zededa - wrong directory?"
    exit 1
fi

# Remove any additional WiFi passwords
cp -p etc/wpa_supplicant/wpa_supplicant.conf.zededa etc/wpa_supplicant/wpa_supplicant.conf

# /usr/local/etc/zededa/ should just have
# onboard.cert.pem onboard.key.pem
# lisp.config.base  root-certificate.pem  server

rm usr/local/etc/zededa/{device.cert.pem,device.key.pem,hwstatus.json,lisp.config,swstatus.json,uuid,zedrouterconfig.json,zedserverconfig}

echo "Remaining files in usr/local/etc/zededa:"
ls usr/local/etc/zededa

rm -rf var/run/zedmanager
rm -rf var/run/zedrouter
rm -rf var/run/xenmgr
rm -rf var/run/identitymgr
rm -rf var/run/downloader
rm -rf var/run/verifier

# Preserve var/tmp/zedmanager/downloads
rm -rf var/tmp/zedmanager/config/*
rm -rf var/tmp/zedrouter/config/*
rm -rf var/tmp/xenmgr/config/*
rm -rf var/tmp/identitymgr/config/*
rm -rf var/tmp/downloader/config/*
rm -rf var/tmp/verifier/config/*

rm -rf var/log/zedmanager*
rm -rf var/log/zedrouter*
rm -rf var/log/xenmgr*
rm -rf var/log/identitymgr*
rm -rf var/log/downloader*
rm -rf var/log/verifier*
rm -rf var/log/xen/


