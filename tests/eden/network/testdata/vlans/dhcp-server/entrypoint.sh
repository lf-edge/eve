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

# DHCP server for apps
cat <<EOF > /etc/dnsmasq.conf
bind-interfaces
except-interface=lo
dhcp-leasefile=/run/dnsmasq.leases
dhcp-range=${eth1},10.2.0.2,10.2.0.254,60m
dhcp-range=${eth1}.100,10.2.100.2,10.2.100.254,60m
dhcp-range=${eth1}.200,10.2.200.2,10.2.200.254,60m
EOF

cat <<EOF > /etc/supervisord.conf
[supervisord]
nodaemon=true

[program:dnsmasq]
command=dnsmasq -d -b -C /etc/dnsmasq.conf
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
redirect_stderr=true

[program:nginx]
command=nginx -g "daemon off;"
autorestart=true
stopsignal=KILL
stopasgroup=true
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
redirect_stderr=true

[program:ip]
command=/bin/sh -c "while true; do sleep 5; ifconfig>/var/www/html/ifconfig.html; done"
autorestart=true
stopsignal=KILL
stopasgroup=true
stdout_logfile=/dev/fd/1
stdout_logfile_maxbytes=0
redirect_stderr=true
EOF

exec /usr/bin/supervisord -c /etc/supervisord.conf