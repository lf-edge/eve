#!/bin/bash
# Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
# for cross-compile

DIR=`pwd`

BUILD_VERSION=`scripts/getversion.sh`
echo "Building version ${BUILD_VERSION}"

mkdir -p var/tmp/zededa/

[ -d bin ] || mkdir bin
[ -d bin/linux_x86_64 ] || mkdir bin/linux_x86_64
[ -d bin/linux_arm64 ] || mkdir bin/linux_arm64

APPS="ledmanager downloader verifier client server register zedrouter domainmgr identitymgr zedmanager eidregister zedagent hardwaremodel dataplane"
if /bin/true; then
    cmdline=""
    for app in $APPS; do
    	cmdline="$cmdline github.com/zededa/go-provision/${app}"
    done
    # echo CMDLINE $cmdline
    go install -v -ldflags -X=main.Version=${BUILD_VERSION} $cmdline
    if [ $? != 0 ]; then
	exit $?
    fi
    for app in $APPS; do
	cp -p bin/${app} bin/linux_x86_64/
    done
    # Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
    GOARCH=arm64 go install -v -ldflags -X=main.Version=${BUILD_VERSION} $cmdline
    # Go install puts them in bin/linux_arm64
    # for app in $APPS; do
    #	    mv ${app} bin/linux_arm64
    # done
fi

# Creating client tar files
TMPDIR=/tmp/zededa-build.$$
# XXX create function for cp+tar

# Setup for untaring in /
# zenbuild will move /opt/zededa/etc to /config

TYPE=linux_arm64
rm -rf $TMPDIR
# Setup for untaring in /
mkdir -p $TMPDIR/config $TMPDIR/opt/zededa/bin $TMPDIR/var/tmp/zededa/
echo ${BUILD_VERSION} >$TMPDIR/opt/zededa/bin/versioninfo
cp -rp DeviceNetworkConfig $TMPDIR/var/tmp/zededa
cp -rp AssignableAdapters $TMPDIR/var/tmp/zededa
cp -p README $TMPDIR/opt/zededa/bin/
cp -p etc/* $TMPDIR/config
cp -p scripts/*.sh $TMPDIR/opt/zededa/bin/
cp -p bin/$TYPE/* $TMPDIR/opt/zededa/bin/
tar -C $TMPDIR/opt/zededa/bin -xf $DIR/dnsmasq.$TYPE.tar.gz
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

TYPE=linux_x86_64
rm -rf $TMPDIR
# Setup for untaring in /
mkdir -p $TMPDIR/config $TMPDIR/opt/zededa/bin $TMPDIR/var/tmp/zededa/
echo ${BUILD_VERSION} >$TMPDIR/opt/zededa/bin/versioninfo
cp -rp DeviceNetworkConfig $TMPDIR/var/tmp/zededa
cp -rp AssignableAdapters $TMPDIR/var/tmp/zededa
cp -p README $TMPDIR/opt/zededa/bin/
cp -p etc/* $TMPDIR/config
cp -p scripts/*.sh $TMPDIR/opt/zededa/bin/
cp -p bin/$TYPE/* $TMPDIR/opt/zededa/bin/
tar -C $TMPDIR/opt/zededa/bin -xf $DIR/dnsmasq.$TYPE.tar.gz
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

