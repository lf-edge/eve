#!/bin/bash
export GOPATH=/home/nordmark/gocode/:/home/nordmark/go-provision
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
DIR=`pwd`

if /bin/true; then
    go install github.com/zededa/go-provision/{client,server,register,zedrouter,xenmgr}
    if [ $? != 0 ]; then
	exit $?
    fi
    cp -p bin/{client,server,register,zedrouter,xenmgr} bin/linux_x86_64/
    GOARCH=arm64 go build -v github.com/zededa/go-provision/client
    GOARCH=arm64 go build -v github.com/zededa/go-provision/server
    GOARCH=arm64 go build -v github.com/zededa/go-provision/register
    GOARCH=arm64 go build -v github.com/zededa/go-provision/zedrouter
    GOARCH=arm64 go build -v github.com/zededa/go-provision/xenmgr
    mv {client,server,register,zedrouter,xenmgr} bin/linux_arm64
fi

# Creating client tar files
TMPDIR=/tmp/zededa-build.$$
# XXX create function for cp+tar

TYPE=linux_arm64
rm -rf $TMPDIR
mkdir -p $TMPDIR/etc/zededa $TMPDIR/bin/zededa
cp -p README $TMPDIR/bin/zededa/
cp -p etc/* $TMPDIR/etc/zededa
cp -p *.sh $TMPDIR/bin/zededa
cp -p bin/$TYPE/{client,server,register,zedrouter,xenmgr} $TMPDIR/bin/zededa
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

TYPE=linux_x86_64
rm -rf $TMPDIR
mkdir -p $TMPDIR/etc/zededa $TMPDIR/bin/zededa
cp -p README $TMPDIR/bin/zededa/
cp -p etc/* $TMPDIR/etc/zededa
cp -p *.sh $TMPDIR/bin/zededa
cp -p bin/$TYPE/{client,server,register,zedrouter,xenmgr} $TMPDIR/bin/zededa
(cd $TMPDIR; tar -cf $DIR/go-provision.$TYPE.tar.gz .)
rm -rf $TMPDIR

