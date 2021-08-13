#!/bin/sh

interfaces=$(ifconfig | grep "^\w" | grep -v LOOPBACK | cut -d: -f1)
eth1=$(echo "$interfaces" | awk 'NR==2')

ip addr add 10.2.0.1/24 dev "${eth1}"

# Configure VLAN sub-interfaces
ip link add link "${eth1}" name "${eth1}.100" type vlan id 100
ip link set dev "${eth1}.100" up
ip addr add 10.2.100.1/24 dev "${eth1}.100"

ip link add link "${eth1}" name "${eth1}.200" type vlan id 200
ip link set dev "${eth1}.200" up
ip addr add 10.2.200.1/24 dev "${eth1}.200"

# DHCP server for apps without VLANs
cat <<EOF > /etc/dnsmasq.conf
bind-interfaces
except-interface=lo
dhcp-leasefile=/run/dnsmasq.leases
interface=${eth1}
dhcp-range=10.2.0.2,10.2.0.254,60m
EOF

# DHCP server for VLAN 100
cat <<EOF > /etc/dnsmasq.100.conf
bind-interfaces
except-interface=lo
dhcp-leasefile=/run/dnsmasq.100.leases
interface=${eth1}.100
dhcp-range=10.2.100.2,10.2.100.254,60m
EOF

# DHCP server for VLAN 200
cat <<EOF > /etc/dnsmasq.200.conf
bind-interfaces
except-interface=lo
dhcp-leasefile=/run/dnsmasq.200.leases
interface=${eth1}.200
dhcp-range=10.2.200.2,10.2.200.254,60m
EOF

cat <<EOF > /etc/supervisord.conf
[supervisord]
nodaemon=true

[program:dnsmasq]
command=dnsmasq -d -b -C /etc/dnsmasq.conf

[program:dnsmasq.100]
command=dnsmasq -d -b -C /etc/dnsmasq.100.conf

[program:dnsmasq.200]
command=dnsmasq -d -b -C /etc/dnsmasq.200.conf

[program:nginx]
command=nginx -g "daemon off;"
autorestart=true
stopsignal=KILL
stopasgroup=true

[program:ip]
command=/bin/sh -c "while true; do sleep 5; ifconfig>/var/www/html/ifconfig.html; done"
autorestart=true
stopsignal=KILL
stopasgroup=true
EOF

exec /usr/bin/supervisord -c /etc/supervisord.conf