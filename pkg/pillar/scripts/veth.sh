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
     up) TASK="$2"
         VIF_NAME="$3"
         VIF_CTR="$3".1
         VIF_BRIDGE="$4"
         VIF_MAC="$5"
         ;;
      *) echo "ERROR: correct use is $0 up TASK VIF_NAME VIF_BRIDGE [VIF_MAC] or $0 down VIF_NAME"
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

VIF_TASK=/run/tasks/vifs/"$TASK"

mkdir -p "$VIF_TASK"
mkdir -p "$VIF_TASK"/var/lib/dhcpcd
mkdir -p "$VIF_TASK"/etc
mkdir -p "$VIF_TASK"/run/dhcpcd/resolv.conf
touch "$VIF_TASK"/etc/resolv.conf

# we use patched version of dhcpcd with /etc/resolv.conf.new
MOUNTS="mount --bind $VIF_TASK/run/dhcpcd/resolv.conf /run/dhcpcd/resolv.conf &&\
 mount --bind $VIF_TASK/var/lib/dhcpcd /var/lib/dhcpcd &&\
 mount --bind $VIF_TASK/etc/resolv.conf /etc/resolv.conf.new"

try nsenter -t "$VIF_NS" -n unshare --mount sh -c "$MOUNTS && dhcpcd $VIF_CTR"
