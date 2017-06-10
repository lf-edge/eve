#!/bin/bash
# Run this after reboot of host to prepare to run Xen domUs

# Special hikey - turn off bright green led
echo 'none' | sudo tee /sys/class/leds/user_led1/trigger

# Could extract this from e.g. lisp.config
UPLINK=wlan0

# /usr/local/bin/zededa/stop.sh
# Need to delete the default drop rules. Don't really need any lisp rules.
iptables -t raw -D lisp -j DROP
ip6tables -t raw -D lisp -j DROP

# Only we should have rules; cleanup from previous run
iptables -F
ip6tables -F

sysctl -w net.ipv6.conf.all.forwarding=1

echo "Setup underlay NAT"
# For all underlays
iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE

DHCPHOSTSDIR=dhcp-hostsdir
DHCPOPTSDIR=dhcp-optsdir
HOSTSDIR=hostsdir
CONFDIR=confdir
# Underlay and overlay ACLs, respectively
IPTABLESDIR=iptablesdir
IP6TABLESDIR=ip6tablesdir
mkdir ${DHCPHOSTSDIR}
mkdir ${DHCPOPTSDIR}
mkdir ${HOSTSDIR}
mkdir ${CONFDIR}
mkdir ${IPTABLESDIR}
mkdir ${IP6TABLESDIR}

# We assume xen${APPNUM}.template exists with the blk and name etc
# We will append the vif and uuid config to those templates

# This belongs in ZedMgr
echo "Setup disk loopback"
losetup /dev/loop3 ubuntu-cloudimg.img
losetup /dev/loop4 xxx-test.img 
losetup /dev/loop5 two-cloudimg.img

# Need to refactor to handle different number of underlays (0/1) and overlays (N)
setup_app() {
    APPNUM=$1
    OLNUM=$2
    OLADDR2=$3
    echo "setup_app: appnum ${APPNUM} olnum ${OLNUM} EID ${OLADDR2}"
    
    UUID=`/usr/bin/uuidgen`
    OLIFNAME=bo${OLNUM}_${APPNUM}
    OLADDR1=fd00::${OLNUM}:${APPNUM}
    ULIFNAME=bu${APPNUM}
    ULADDR1=172.27.${APPNUM}.1
    ULADDR2=172.27.${APPNUM}.2
    # Room to handle multiple underlays in 5th byte
    ULMAC="00:16:3e:0:0:${APPNUM}"
    OLMAC="00:16:3e:1:${OLNUM}:${APPNUM}"

    ip link add xenbr2 type bridge
    ip link set xenbr2 name ${OLIFNAME}
    # DNS address
    echo ifconfig ${OLIFNAME} inet6 add ${OLADDR1}/128 up
    ifconfig ${OLIFNAME} inet6 add ${OLADDR1}/128 up
    ip -6 route add ${OLADDR2}/128 dev ${OLIFNAME}
    ip link add xenbr2 type bridge
    ip link set xenbr2 name ${ULIFNAME}
    echo ifconfig ${ULIFNAME} ${ULADDR1}/24 up
    ifconfig ${ULIFNAME} ${ULADDR1}/24 up

    # XXX doesn't appear to be needed
    # XXX check if it solves the RA's not being sent!! NOT
    # XXX try again with /8 interface address
    # echo "dhcp-range=interface:${OLIFNAME},${OLADDR2},off-link,8" > ${CONFDIR}/dhcpv6.${OLNUM}_${APPNUM}.conf
    echo "${ULMAC},id:*,${ULADDR2}" > ${DHCPHOSTSDIR}/dhcpv4.${APPNUM}
    # Brackets needed for IPv6
    echo "${OLMAC},[${OLADDR2}]" > ${DHCPHOSTSDIR}/dhcpv6.${OLNUM}_${APPNUM}
    # Set up domain-search list for overlay. Use uuid.local
    echo "tag:${OLIFNAME},option6:domain-search,${UUID}.local" >${DHCPOPTSDIR}/dhcpv6.${OLNUM}_${APPNUM}

    # Per overlay names?
    # We return a separate search option based on UUID as here.
    # Alternative would be to use separate namespace or separate dns server in
    # domZ based on the client interface. Risk is that a client who can
    # guess the UUID for some other domU can lookup the EIDs (but not send to)
    # the in another IID.

    # Create a hosts file with appended names. Assumes no trailing spaces in
    # /etc/hosts
    # XXX need the app names from the instance
    grep zed /etc/hosts | sed "s/$/.${UUID}.local/" >${HOSTSDIR}/hosts6.${OLNUM}_${APPNUM}

    cp xen${APPNUM}.template xen${APPNUM}.cfg
    cat <<EOF >>xen${APPNUM}.cfg
# UUID
uuid = "$UUID"

# Network devices
# Need fixed mac for at least IPv4
vif = [ 'bridge=${ULIFNAME},vifname=n${ULIFNAME},mac=${ULMAC}', 'bridge=${OLIFNAME},vifname=n${OLIFNAME},mac=${OLMAC}' ]
EOF
    # Create ip6tables file for overlay
    cat <<EOF >${IPTABLESDIR}/iptables.${APPNUM}
# XXX First two lines is for ping testing. Remove
iptables -A FORWARD -i ${ULIFNAME} -m set --match-set ipv4.google.com dst -j ACCEPT
iptables -A FORWARD -o ${ULIFNAME} -m set --match-set ipv4.google.com src -j ACCEPT
iptables -A FORWARD -i ${ULIFNAME} -m set --match-set ipv4.zededa.net dst -j ACCEPT
iptables -A FORWARD -o ${ULIFNAME} -m set --match-set ipv4.zededa.net src -j ACCEPT
iptables -A FORWARD -i ${ULIFNAME} -d 23.72.199.210 -j ACCEPT
iptables -A FORWARD -o ${ULIFNAME} -s 23.72.199.210 -j ACCEPT
iptables -A FORWARD -i ${ULIFNAME} -j DROP
iptables -A FORWARD -o ${ULIFNAME} -j DROP
EOF
    echo "Applying rules from ${IPTABLESDIR}/iptables.${APPNUM}"
    source ${IPTABLESDIR}/iptables.${APPNUM}

    # Should we create an ipset with all the EID for each overlay instance?
    # Apply all eids to this each ${OLIFNAME}
    # XXX need to have a list per IID, or tagged with IIDs so we can grep
    # plus IID for OLIFNAME?
    sed "s/eids/eids.${OLIFNAME}/" ipset.all-eids >ipset.all-eids.${OLIFNAME}
    ipset restore -f ipset.all-eids.${OLIFNAME}
    
    cat <<EOF >${IP6TABLESDIR}/ip6tables.${OLNUM}_${APPNUM}
# First two rules assume there might be IPv6 underlay connectivity
ip6tables -A FORWARD -i ${OLIFNAME} -m set --match-set ipv6.zededa.net dst -j ACCEPT
ip6tables -A FORWARD -o ${OLIFNAME} -m set --match-set ipv6.zededa.net src -j ACCEPT
ip6tables -A FORWARD -i ${OLIFNAME} -m set --match-set eids.${OLIFNAME} dst -j ACCEPT
ip6tables -A FORWARD -o ${OLIFNAME} -m set --match-set eids.${OLIFNAME} src -j ACCEPT
ip6tables -A FORWARD -i ${OLIFNAME} -j DROP
ip6tables -A FORWARD -o ${OLIFNAME} -j DROP
EOF
    echo "Applying rules from ${IP6TABLESDIR}/ip6tables.${OLNUM}_${APPNUM}"
    source ${IP6TABLESDIR}/ip6tables.${OLNUM}_${APPNUM}
}

echo "Create example ipset's"
# Note that we need to restart dnsmasq if we add to ${CONFDIR}
ipset create ipv6.google.com hash:ip family inet6
ipset create ipv4.google.com hash:ip family inet
ipset create ipv6.zededa.net hash:ip family inet6
ipset create ipv4.zededa.net hash:ip family inet
cat <<EOF >${CONFDIR}/ipset.test.conf
ipset=/google.com/ipv4.google.com,ipv6.google.com
ipset=/zededa.net/ipv4.zededa.net,ipv6.zededa.net
EOF

# Stick all the EIDs in here for now. Need one per application bundle?
ipset create eids hash:ip family inet6
# zedcontrol
ipset add eids fd45:efca:3607:4c1d:eace:a947:3464:d21e
# bobo
ipset add eids fdd5:79bf:7261:d9df:aea1:c8d2:842d:b99b
# hikey
ipset add eids fd07:cfa2:2b35:b8f6:d6f6:e9be:7d2a:fc93
# hikey app1
ipset add eids fd13:4e7f:e66d:2822:a5ce:f644:bebe:30ae
# hikey app2
ipset add eids fd41:e868:cc59:c3a0:90cc:9853:18c5:5635
# hikey app3
ipset add eids fd00:82ff:a727:fb30:a4c2:f612:7efb:bac6
# hikey app4
ipset add eids fd31:447f:256b:b6dd:5c6c:addd:66b1:c760

ipset save eids >ipset.all-eids

# Application 1, overlay 1
# XXX Using app1 EID
setup_app 1 1 fd13:4e7f:e66d:2822:a5ce:f644:bebe:30ae

# Application 2, overlay 1
# XXX Using app3 EID
setup_app 2 1 fd00:82ff:a727:fb30:a4c2:f612:7efb:bac6

DEBUGOPTS="-d -q --log-dhcp"
OPTS="--enable-ra --except-interface ${UPLINK} --no-ping"
# XXX should we set --ra-param to set the max lifetime?
# XXX makes no difference to set --ra-param=bo*,high,600,30000
# XXX should we set --bogus-priv --stop-dns-rebind --rebind-localhost-ok --domain-needed
OPTS="${OPTS} --bogus-priv --stop-dns-rebind --rebind-localhost-ok --domain-needed"

# XXX note that --bridge-interface=lo,bo* goes with a hack to get lo0 matches
# what is a better hack? Really want per intf ra control even when there are
# no prefixes.

echo "Starting dnsmasq"
echo /home/nordmark/dnsmasq-2.75/src/dnsmasq ${DEBUGOPTS} ${OPTS}  --hostsdir=${HOSTSDIR} --dhcp-hostsdir=${DHCPHOSTSDIR} --dhcp-optsdir=${DHCPOPTSDIR} --conf-dir=${CONFDIR} --dhcp-range=172.27.0.0,static,255.255.0.0,infinite --dhcp-range=::,static,defrtr,0,infinite --bridge-interface=lo,bo*

/home/nordmark/dnsmasq-2.75/src/dnsmasq ${DEBUGOPTS} ${OPTS} --hostsdir=${HOSTSDIR} --dhcp-hostsdir=${DHCPHOSTSDIR} --dhcp-optsdir=${DHCPOPTSDIR} --conf-dir=${CONFDIR} --dhcp-range=172.27.0.0,static,255.255.0.0,infinite --dhcp-range=::,static,defrtr,0,infinite --bridge-interface=lo,bo*
