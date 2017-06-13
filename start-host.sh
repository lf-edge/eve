#!/bin/bash
# Run this after reboot of host to prepare to run Xen domUs
RUNDIR=/var/run/zedrouter/
# XXX should we pick a directory?
XENDIR=`pwd`
# XXX also add a IMGDIR for the losetup??

# Special hikey - turn off bright green led
echo 'none' | sudo tee /sys/class/leds/user_led1/trigger

# Could extract this from e.g. lisp.config
UPLINK=wlan0

# Need to delete the default drop rules. Don't really need any lisp rules.
iptables -t raw -D lisp -j DROP
ip6tables -t raw -D lisp -j DROP

# Only we should have rules; cleanup from previous run
iptables -F
ip6tables -F

sysctl -w net.ipv6.conf.all.forwarding=1

echo "Setup underlay NAT"
# For all underlays
# XXX should we just apply it to -i ${ULIFNAME} somehow?? -i not avail.
iptables -t nat -A POSTROUTING -o $UPLINK -j MASQUERADE

mkdir -p ${RUNDIR}
DHCPHOSTSDIR=${RUNDIR}/dhcp-hostsdir
DHCPOPTSDIR=${RUNDIR}/dhcp-optsdir
HOSTSDIR=${RUNDIR}/hostsdir
CONFDIR=${RUNDIR}/confdir
# Underlay and overlay ACLs, respectively
IPTABLESDIR=${RUNDIR}/iptablesdir
IP6TABLESDIR=${RUNDIR}/ip6tablesdir
IPSETDIR=${RUNDIR}/ipset

# Start clean
rm -rf ${DHCPHOSTSDIR} ${DHCPOPTSDIR} ${HOSTSDIR} ${CONFDIR} ${IPTABLESDIR} ${IP6TABLESDIR} ${IPSETDIR}
mkdir ${DHCPHOSTSDIR} ${DHCPOPTSDIR} ${HOSTSDIR} ${CONFDIR} ${IPTABLESDIR} ${IP6TABLESDIR} ${IPSETDIR}


# We assume ${XENDIR}/xen${APPNUM}.template exists with the blk and name etc
# We will append the vif and uuid config to those templates

# This belongs in ZedMgr
echo "Setup disk loopback"
if [ ! -f ubuntu-cloudimg.img ]; then
    echo "Missing ubuntu-cloudimg.img"
    exit 1
fi
losetup /dev/loop3 ubuntu-cloudimg.img
if [ ! -f xxx-test.img ]; then
    echo "Missing xxx-test.img"
    exit 1
fi
losetup /dev/loop4 xxx-test.img 
if [ ! -f two-cloudimg.img ]; then
    echo "Missing two-cloudimg.img"
    exit 1
fi
losetup /dev/loop5 two-cloudimg.img

# Need to refactor to handle different number of underlays (0/1) and overlays (N)
setup_app() {
    APPNUM=$1
    OLNUM=$2
    OLADDR2=$3
    echo "setup_app: appnum ${APPNUM} olnum ${OLNUM} EID ${OLADDR2}"
    if [ ! -f ${XENDIR}/xen${APPNUM}.template ]; then
	echo "Missing ${XENDIR}/xen${APPNUM}.template"
	exit 1
    fi

    # XXX would like to keep the same UUID as before to avoid issues
    # with old lease resulting in old /etc/resolv.conf in domU
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

    # XXX remove all changes to dnsmasq but one < 64 check.
    # XXX doesn't appear to be needed
    # XXX check if it solves the RA's not being sent!! NOT
    # XXX try again with /8 interface address
    # echo "dhcp-range=interface:${OLIFNAME},${OLADDR2},off-link,8" > ${CONFDIR}/dhcpv6.${OLNUM}_${APPNUM}.conf
    # echo "${ULMAC},id:*,${ULADDR2}" > ${DHCPHOSTSDIR}/dhcpv4.${APPNUM}
    # Brackets needed for IPv6
    # echo "${OLMAC},[${OLADDR2}]" > ${DHCPHOSTSDIR}/dhcpv6.${OLNUM}_${APPNUM}

    # Start clean
    pkill -u radvd -f radvd.${OLIFNAME}.conf
    # Enable radvd on interface
    cat <<EOF >>/etc/radvd.conf
interface ${OLIFNAME} {
	IgnoreIfMissing on;
	AdvSendAdvert on;
	MaxRtrAdvInterval 1800;
	AdvManagedFlag on;
};
EOF
    radvd -u radvd -C /etc/radvd.${OLIFNAME}.conf -p /var/run/radvd/radvd.${OLIFNAME}.pid

    # Set up domain-search list for overlay. Use uuid.local
    # XXX remove
    # echo "tag:${OLIFNAME},option6:domain-search,${UUID}.local" >${DHCPOPTSDIR}/dhcpv6.${OLNUM}_${APPNUM}

    # Create a hosts file with appended names. Assumes no trailing spaces in
    # /etc/hosts
    # XXX need the app names from the instance
    grep zed /etc/hosts >${HOSTSDIR}/hosts6.${OLNUM}_${APPNUM}

    # Start clean
    pkill -u nobody -f dnsmasq.${OLIFNAME}.conf 
    pkill -u nobody -f dnsmasq.${ULIFNAME}.conf

    # XXX having a shorter lifetime avoids issues with stale lease when uuid
    # changes. Remove once we have a fixed UUID per app instance.
    # XXX separate hostsdir per instance/interface means no UUID - just short names
    LEASE_TIME=1h
    cat <<EOF >/etc/dnsmasq.${OLIFNAME}.conf
pid-file=/var/run/dnsmasq.${OLIFNAME}.pid
interface=${OLIFNAME}
except-interface=lo
listen-address=${OLADDR1}
bind-interfaces
log-queries
log-dhcp
no-hosts
addn-hosts=${HOSTSDIR}/hosts6.${OLNUM}_${APPNUM}
no-ping
bogus-priv
stop-dns-rebind
rebind-localhost-ok
domain-needed
# XXX needed? dhcp-range=${OLADDR2},off-link,8
dhcp-host=${OLMAC},[${OLADDR2}]
dhcp-range=::,static,0,${LEASE_TIME}
EOF

    cat <<EOF >/etc/dnsmasq.${ULIFNAME}.conf
pid-file=/var/run/dnsmasq.${ULIFNAME}.pid
interface=${ULIFNAME}
except-interface=lo
listen-address=${ULADDR1}
bind-interfaces
log-queries
log-dhcp
no-hosts
no-ping
bogus-priv
stop-dns-rebind
rebind-localhost-ok
domain-needed
# SHOULD be derived from underlay ACL
ipset=/google.com/ipv4.google.com,ipv6.google.com
ipset=/zededa.net/ipv4.zededa.net,ipv6.zededa.net
dhcp-host=${ULMAC},id:*,${ULADDR2}
dhcp-range=172.27.0.0,static,255.255.0.0,${LEASE_TIME}
EOF

    DMDIR=/home/nordmark/dnsmasq-2.75/src
    ${DMDIR}/dnsmasq --conf-file=/etc/dnsmasq.${OLIFNAME}.conf
    ${DMDIR}/dnsmasq --conf-file=/etc/dnsmasq.${ULIFNAME}.conf
    
    cp ${XENDIR}/xen${APPNUM}.template ${XENDIR}/xen${APPNUM}.cfg
    cat <<EOF >>${XENDIR}/xen${APPNUM}.cfg
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
iptables -A FORWARD -i ${ULIFNAME} -j DROP
iptables -A FORWARD -o ${ULIFNAME} -j DROP
EOF
    echo "Applying rules from ${IPTABLESDIR}/iptables.${APPNUM}"
    source ${IPTABLESDIR}/iptables.${APPNUM}

    # Should we create an ipset with all the EID for each overlay instance?
    # Apply all eids to this each ${OLIFNAME}
    # XXX need to have a list per IID, or tagged with IIDs so we can grep
    # plus IID for OLIFNAME?
    # Start clean
    ipset destroy eids.${OLIFNAME} || /bin/true
    sed "s/eids/eids.${OLIFNAME}/" ${IPSETDIR}/all-eids >${IPSETDIR}/all-eids.${OLIFNAME}
    ipset restore -f ${IPSETDIR}/all-eids.${OLIFNAME}
    
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

echo "Create underlay ipset's"
ipset create ipv6.google.com hash:ip family inet6 || ipset flush ipv6.google.com
ipset create ipv4.google.com hash:ip family inet || ipset flush ipv4.google.com
ipset create ipv6.zededa.net hash:ip family inet6 || ipset flush ipv6.zededa.net
ipset create ipv4.zededa.net hash:ip family inet || ipset flush ipv4.zededa.net
# XXX remove
# cat <<EOF >${CONFDIR}/ipset.test.conf
# ipset=/google.com/ipv4.google.com,ipv6.google.com
# ipset=/zededa.net/ipv4.zededa.net,ipv6.zededa.net
# EOF

# Stick all the EIDs in here for now. Need one per application bundle?
ipset create eids hash:ip family inet6 || ipset flush eids
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

ipset save eids >${IPSETDIR}/all-eids

# Application 1, overlay 1
# XXX Using app1 EID
setup_app 1 1 fd13:4e7f:e66d:2822:a5ce:f644:bebe:30ae

# Application 3, overlay 1
# XXX Using app3 EID
setup_app 3 1 fd00:82ff:a727:fb30:a4c2:f612:7efb:bac6

