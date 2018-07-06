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

echo ${BUILD_VERSION} >bin/versioninfo
echo ${BUILD_VERSION} >bin/linux_x86_64/versioninfo
echo ${BUILD_VERSION} >bin/linux_arm64/versioninfo

APPS="zedbox"
APPS1="logmanager ledmanager downloader verifier client zedrouter domainmgr identitymgr zedmanager zedagent hardwaremodel"

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

for app in $APPS1; do
    rm -f bin/${app} bin/linux_x86_64/${app} bin/linux_arm64/${app}
    ln -s $APPS bin/${app}
    ln -s $APPS bin/linux_x86_64/${app}
    ln -s $APPS bin/linux_arm64/${app}
done
