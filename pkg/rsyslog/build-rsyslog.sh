#!/bin/sh

git clone -b v8-stable https://github.com/rsyslog/rsyslog.git
cd rsyslog || exit
git checkout ceafdcdfd9c00b97c4f2a57f3d3a2b0b950f76b0
mkdir -p contrib/imemlogd
git apply ../imemlogd.diff
mkdir utils
echo "./configure --prefix=/usr/local $RSYSLOG_CONFIGURE_OPTIONS" --enable-compile-warnings=yes > utils/conf
chmod +x utils/conf

autoreconf -fvi && utils/conf && make -j2 && make install || exit $?

strip /usr/local/sbin/rsyslogd
