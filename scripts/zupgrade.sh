#!/bin/sh

die() { echo $@; exit 2; }
[ $# -ne 1 ] && die "Need URL to download package from."
url=$1
pkg=$(basename $1)
sudo dpkg -P zededa-provision
dpkg -s gdebi-core >/dev/null 2>&1 || apt-get install -y gdebi-core
wget -q $url && sudo gdebi -n $pkg
