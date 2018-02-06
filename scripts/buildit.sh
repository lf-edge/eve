#!/bin/bash
# Assumes chown `whoami` /usr/local/go/pkg/; chgrp `whoami` /usr/local/go/pkg/
# for cross-compile

DIR=`pwd`

GIT_TAG=`git tag`
BUILD_DATE=`date -u +"%Y-%m-%d-%H:%M"`
GIT_VERSION=`git describe --match v --abbrev=8 --always --dirty`
BRANCH_NAME=`git rev-parse --abbrev-ref HEAD`
VERSION=${GIT_TAG}

# XXX note that if PROD is changed things to not get rebuilt
if [ ! -z ${PROD+x} ]; then
	EXTRA_VERSION=""
else
	EXTRA_VERSION=-${GIT_VERSION}-${BUILD_DATE}
fi

if [ ${BRANCH_NAME} = "master" ]; then
	BUILD_VERSION=${VERSION}${EXTRA_VERSION}
else
	BUILD_VERSION=${VERSION}-${GIT_BRANCH}${EXTRA_VERSION}
fi
echo "Building version ${BUILD_VERSION}"
mkdir -p var/tmp/zededa/
echo "all: ${BUILD_VERSION}" >var/tmp/zededa/version_tag

[ -d bin ] || mkdir bin
[ -d bin/linux_x86_64 ] || mkdir bin/linux_x86_64
[ -d bin/linux_arm64 ] || mkdir bin/linux_arm64

export GOPATH=$DIR
for mod in github.com/golang/protobuf/proto \
	       github.com/fsnotify/fsnotify \
               github.com/satori/go.uuid \
               golang.org/x/crypto/ocsp \
               github.com/nanobox-io/golang-scribble \
               github.com/vishvananda/netlink \
               github.com/RevH/ipinfo \
               github.com/shirou/gopsutil/net \
			   github.com/aws/aws-sdk-go/aws \
			   github.com/pkg/sftp
do
    echo $mod
    go get -u $mod
done

# Use ../api sandbox for shared proto files
export GOPATH=$GOPATH:$DIR/../api

APPS="downloader verifier client server register zedrouter domainmgr identitymgr zedmanager eidregister zedagent"
cmdline=""
for app in $APPS; do
    echo $app
    cmdline="github.com/zededa/go-provision/${app}"
    CGO_ENABLED=0 GOARCH=amd64 GOOS=linux go build -o bin/linux_x86_64/${app} $cmdline
    CGO_ENABLED=0 GOARCH=arm64 GOOS=linux go build -o bin/linux_arm64/${app} $cmdline
done

# Creating client tar files
TMPDIR=/tmp/zededa-build.$$
# XXX create function for cp+tar

TYPE=linux_arm64
rm -rf $TMPDIR
# Setup for untaring in /opt
# zenbuild will move /opt/zededa/etc to /config
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

