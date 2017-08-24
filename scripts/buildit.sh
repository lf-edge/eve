#!/bin/bash
# Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
# for cross-compile

export GOPATH=/home/nordmark/gocode/:/home/nordmark/go-provision
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
DIR=`pwd`

APPS="downloader verifier client server register zedrouter domainmgr identitymgr zedmanager eidregister"
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
mkdir -p $TMPDIR/etc/zededa $TMPDIR/bin/zededa
cp -p README $TMPDIR/bin/zededa/
cp -p etc/* $TMPDIR/etc/zededa/
cp -p scripts/*.sh $TMPDIR/bin/zededa/
cp -p bin/$TYPE/* $TMPDIR/bin/zededa/
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

TYPE=linux_x86_64
rm -rf $TMPDIR
mkdir -p $TMPDIR/etc/zededa $TMPDIR/bin/zededa
cp -p README $TMPDIR/bin/zededa/
cp -p etc/* $TMPDIR/etc/zededa/
cp -p scripts/*.sh $TMPDIR/bin/zededa/
cp -p bin/$TYPE/* $TMPDIR/bin/zededa/
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

