#!/bin/sh
set -e

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

TASK="$2"
VIF_TASK=/run/tasks/vifs/"$TASK"

case $1 in
down)
  unshare --mount --root="$VIF_TASK" dhcpcd --exit || :
  umount "$VIF_TASK"/etc/dhcpcd.conf || :
  umount "$VIF_TASK"/lib || :
  umount "$VIF_TASK"/usr/lib || :
  umount "$VIF_TASK"/bin || :
  umount "$VIF_TASK"/usr/bin || :
  umount "$VIF_TASK"/sbin || :
  rm -rf "$VIF_TASK"
  ;;
up)
  VIF_NS=$(jq '.pid')
  mkdir -p "$VIF_TASK"

  # mount files and directories required to run dhcpcd

  mkdir -p "$VIF_TASK"/etc
  touch "$VIF_TASK"/etc/dhcpcd.conf
  mount --bind /etc/dhcpcd.conf "$VIF_TASK"/etc/dhcpcd.conf

  mkdir -p "$VIF_TASK"/lib
  mount --bind /lib "$VIF_TASK"/lib

  mkdir -p "$VIF_TASK"/usr/lib
  mount --bind /usr/lib "$VIF_TASK"/usr/lib

  mkdir -p "$VIF_TASK"/bin
  mount --bind /bin "$VIF_TASK"/bin

  mkdir -p "$VIF_TASK"/sbin
  mount --bind /sbin "$VIF_TASK"/sbin

  mkdir -p "$VIF_TASK"/usr/bin
  mount --bind /usr/bin "$VIF_TASK"/usr/bin

  nsenter --target "$VIF_NS" --net unshare --uts --mount --root="$VIF_TASK" dhcpcd
  ;;
*)
  echo "ERROR: correct use is $0 up TASK or $0 down TASK"
  exit 2
  ;;
esac
