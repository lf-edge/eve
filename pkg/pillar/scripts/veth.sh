#!/bin/sh
set -e

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

try() {
   if ! "$@"; then
      ip link del "$VIF_CTR" || :
      ip link del "$VIF_NAME" || :
      exit 1
   fi
}

VIF_NS=$(jq '.pid')
case $1 in
   down) ip link del "$2"
         exit $?
         ;;
     up) VIF_NAME="$2"
         VIF_CTR="$2".1
         VIF_BRIDGE="$3"
         VIF_MAC="$4"
         ;;
      *) echo "ERROR: correct use is $0 up VIF_NAME VIF_BRIDGE [VIF_MAC] or $0 down VIF_NAME"
         exit 2
esac


try ip link add "$VIF_CTR" type veth peer name "$VIF_NAME"
try ip link set "$VIF_CTR" netns "$VIF_NS"
if [ "$VIF_MAC" ]; then
   try nsenter -t "$VIF_NS" -n ifconfig "$VIF_CTR" hw ether "$VIF_MAC"
fi

try brctl addif "$VIF_BRIDGE" "$VIF_NAME"

try nsenter -t "$VIF_NS" -n ip link set "$VIF_CTR" up
try ip link set "$VIF_NAME" up
