#!/bin/sh

if [ $# -eq 0 ] ; then
   echo "Usage: $0 [-|shell_script]"
   echo "       specifying - instead of a shell script will generate tarball.gz on stdout"
elif [ "$1" = "-" ] ; then
   tar -C /bits -czf - .
else
   bash -c "$*"
fi
