#!/bin/sh

git clone -b v8-stable https://github.com/rsyslog/rsyslog.git
cd rsyslog || exit
mkdir -p contrib/imemlogd
cp ../imemlogd.c contrib/imemlogd/imemlogd.c
cp ../Makefile.am.imemlogd contrib/imemlogd/Makefile.am
cp ../Makefile.am.tests tests/Makefile.am
cp ../Makefile.am Makefile.am
cp ../configure.ac configure.ac
git pull
mkdir utils
echo "./configure --prefix=/usr/local $RSYSLOG_CONFIGURE_OPTIONS" --enable-compile-warnings=yes > utils/conf
chmod +x utils/conf

autoreconf -fvi && utils/conf && make -j2 && make install || exit $?
