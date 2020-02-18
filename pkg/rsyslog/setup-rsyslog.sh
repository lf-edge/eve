#!/bin/sh

git clone -b v8-stable https://github.com/rsyslog/rsyslog.git
cd rsyslog || exit
mkdir -p contrib/imemlogd
cp ../imemlogd.diff imemlogd.diff
git apply imemlogd.diff
mkdir utils
echo "./configure --prefix=/usr/local $RSYSLOG_CONFIGURE_OPTIONS" --enable-compile-warnings=yes > utils/conf
chmod +x utils/conf

autoreconf -fvi && utils/conf && make -j2 && make install || exit $?
