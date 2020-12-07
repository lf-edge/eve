#!/bin/busybox sh

# This script is sourced from
# https://github.com/debian-pi/raspbian-ua-netinst/blob/master/scripts/etc/udhcpc/default.script
# and modified as per EVE requirement

: "${staticroutes:=}"
: "${ip:=}"
: "${hostname:=}"

[ -z "$1" ] && echo 'Error: should be called from udhcpc' && exit 1

# create etc directory if not already done
mkdir -p /mnt/rootfs/etc

# save config information for $interface
CFG="/mnt/rootfs/etc/udhcpc.${interface}.cfg"

RESOLV_CONF='/mnt/rootfs/etc/resolv.conf'
RESOLV_OPTIONS="rotate timeout:10 attempts:5"

# interface for which DNS is to be configured
PEERDNS_IF=eth0

update_ip_hosts()
{
    if [ -n "$1" ]; then
      if [ -n "$2" ]; then
          # refresh ips for renew
          sed -i "s/$1/$2/g" /mnt/rootfs/etc/hosts
      else
          # delete removed ip
          sed -i "/$1/d" /mnt/rootfs/etc/hosts
      fi
    fi
}

update_hosts()
{
    if [ -n "${hostname}" ] && [ "${hostname}" != "(none)" ]; then
      if [ -n "$(hostname)" ] && [ "$(hostname)" != "${hostname}" ]; then
            # if hostname changed, update it
            sed -i "s/$(hostname)/${hostname}/g" /mnt/rootfs/etc/hosts
            echo "${hostname}" > /mnt/rootfs/etc/hostname
            hostname -F /mnt/rootfs/etc/hostname
      fi
      if ! grep -Fxq "${ip}" /mnt/rootfs/etc/hosts; then
            # if ip not defined, add it
            echo "${ip} ${hostname}" >> /mnt/rootfs/etc/hosts
      fi
    fi
}

install_classless_routes()
{
    while [ -n "$1" ] && [ -n "$2" ]; do
        if [ "$2" == '0.0.0.0' ]; then
            ip route add "$1" dev "$interface" src "$ip"
        else
            ip route add "$1" via "$2" dev "$interface"
        fi
        shift 2
    done
}

case "$1" in
  deconfig)
    echo "udhcpc op deconfig interface ${interface}"
    # bring interface up, but with no IP configured
    ip addr flush dev $interface
    ip link set $interface up
    # shellcheck source=/dev/null
    [ -f "$CFG" ] && update_ip_hosts "$(source "${CFG}"; echo "$ip")"
    # remove any stored config info for this $interface
    rm -f $CFG
    ;;
  bound)
    echo "udhcpc op bound interface ${interface}"
    # save config info for $interface
    set > $CFG
    # configure interface and routes
    ip addr flush dev $interface
    ip addr add ${ip}/${mask} dev $interface
    # shellcheck disable=SC2086
    [ -n "$router" ] && [ -n "$staticroutes" ] && install_classless_routes $staticroutes
    # setup dns
    if [ "$interface" == "$PEERDNS_IF" ] ; then
      # remove previous dns
      rm -f $RESOLV_CONF
      [ -n "$domain" ] && echo search $domain > $RESOLV_CONF
      for i in $dns ; do
        echo nameserver $i >> $RESOLV_CONF
      done
      echo "options ${RESOLV_OPTIONS}" >> $RESOLV_CONF
    fi
    update_hosts
    ;;
  renew)
    echo "udhcpc op renew interface ${interface}"
    # compare new vs. previous config info:
    set > ${CFG}.new
    for i in $(diff -U1 $CFG ${CFG}.new | grep -E ^[+-] \
                                        | tail +3 \
                                        | awk -F[+-=] '{print $2}') ; do
      case "$i" in
        ip|mask|router)
          REDO_NET='yes'
          ;;
        domain|dns)
          REDO_DNS='yes'
          ;;
        hostname)
          REDO_HOSTNAME='yes'
          ;;
      esac
    done
    # shellcheck source=/dev/null
    old_ip="$(source "${CFG}"; echo "$ip")"
    # shellcheck disable=SC1090
    old_mask="$(source "${CFG}"; echo "$mask")"
    # save new config info:
    mv -f ${CFG}.new $CFG
    # make only necessary changes, as per config comparison:
    if [ -n "$REDO_NET" ] ; then
      # Do not touch if IP address and mask did not change
      if [ "$old_ip" != "$ip" ] || [ "$old_mask" != "$mask" ] ; then
        ip addr flush dev "$interface"
        ip addr add "${ip}"/"${mask}" dev "$interface"
      fi
      # shellcheck disable=SC2086
      [ -n "$router" ] && [ -n "$staticroutes" ] && install_classless_routes $staticroutes
      update_ip_hosts "$old_ip" $ip
    fi
    if [ -n "$REDO_DNS" -a "$interface" == "$PEERDNS_IF" ] ; then
      # remove previous dns
      rm -f $RESOLV_CONF
      [ -n "$domain" ] && echo search $domain > $RESOLV_CONF
      for i in $dns ; do
        echo nameserver $i >> $RESOLV_CONF
      done
      echo "options ${RESOLV_OPTIONS}" >> $RESOLV_CONF
    fi
    if [ -n "$REDO_HOSTNAME" ]; then
      update_hosts
    fi
    ;;
esac

exit 0
