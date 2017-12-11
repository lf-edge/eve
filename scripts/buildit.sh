#!/bin/bash
# Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
# for cross-compile

DIR=`pwd`

[ -d bin ] || mkdir bin
[ -d bin/linux_x86_64 ] || mkdir bin/linux_x86_64
[ -d bin/linux_arm64 ] || mkdir bin/linux_arm64

APPS="downloader verifier client server register zedrouter domainmgr identitymgr zedmanager eidregister zedagent dataplane"
if /bin/true; then
    cmdline=""
    for app in $APPS; do
    	cmdline="$cmdline github.com/zededa/go-provision/${app}"
    done
    # echo CMDLINE $cmdline
    go install $cmdline
    if [ $? != 0 ]; then
	exit $?
    fi
    for app in $APPS; do
	cp -p bin/${app} bin/linux_x86_64/
    done
    # Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
    GOARCH=arm64 go install -v $cmdline
    # Go install puts them in bin/linux_arm64
    # for app in $APPS; do
    #	    mv ${app} bin/linux_arm64
    # done
fi

# Creating client tar files
TMPDIR=/tmp/zededa-build.$$
# XXX create function for cp+tar

TYPE=linux_arm64
rm -rf $TMPDIR
# Setup for untaring in /opt
mkdir -p $TMPDIR/zededa/etc $TMPDIR/zededa/bin
cp -p README $TMPDIR/zededa/bin/
cp -p etc/* $TMPDIR/zededa/etc/
cp -p scripts/*.sh $TMPDIR/zededa/bin/
cp -p bin/$TYPE/* $TMPDIR/zededa/bin/
tar -C $TMPDIR/zededa/bin -xf $DIR/dnsmasq.$TYPE.tar.gz
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

TYPE=linux_x86_64
rm -rf $TMPDIR
# Setup for untaring in /opt
mkdir -p $TMPDIR/zededa/etc $TMPDIR/zededa/bin
cp -p README $TMPDIR/zededa/bin/
cp -p etc/* $TMPDIR/zededa/etc/
cp -p scripts/*.sh $TMPDIR/zededa/bin/
cp -p bin/$TYPE/* $TMPDIR/zededa/bin/
tar -C $TMPDIR/zededa/bin -xf $DIR/dnsmasq.$TYPE.tar.gz
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

