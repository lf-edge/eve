#!/bin/sh

set -x

interfaces=$(ifconfig | grep "^\w" | grep -v LOOPBACK | cut -d: -f1)
eth0=$(echo "$interfaces" | awk 'NR==1')

ip addr add 10.11.13.1/24 dev "${eth0}"

cat <<EOF > /etc/dnsmasq.conf
bind-interfaces
except-interface=lo
dhcp-leasefile=/run/dnsmasq.leases
interface=${eth0}
dhcp-range=10.11.13.2,10.11.13.254,60m
EOF

cat <<EOF > /etc/supervisord.conf
[supervisord]
nodaemon=true

[program:dnsmasq]
command=dnsmasq -d -b -C /etc/dnsmasq.conf
EOF

exec /usr/bin/supervisord -c /etc/supervisord.conf