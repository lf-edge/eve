#!/bin/bash

ETCDIR=/usr/local/etc/zededa
BINDIR=/usr/local/bin/zededa
PROVDIR=$BINDIR
WAIT=1

while [ $# != 0 ]; do
    if [ "$1" == -w ]; then
	WAIT=0
    else
	ETCDIR=$1
    fi
    shift
done

echo "Configuration from factory/install:"
(cd $ETCDIR; ls -l)
echo

if [ ! \( -f $ETCDIR/device.cert.pem -a -f $ETCDIR/device.key.pem \) ]; then
    echo "Generating a device key pair and self-signed cert (using TPM/TEE if available)"
    $PROVDIR/generate-device.sh $ETCDIR/device
    SELF_REGISTER=1
else
    echo "Using existing device key pair and self-signed cert"
    SELF_REGISTER=0
fi
if [ ! -f $ETCDIR/server -o ! -f $ETCDIR/root-certificate.pem ]; then
    echo "No server or root-certificate to connect to. Done"
    exit 0
fi

if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

# XXX should we harden/remove any Linux network services at this point?

echo "Check for WiFi config"
if [ -f $ETCDIR/wifi_ssid ]; then
    echo -n "SSID: "
    cat $ETCDIR/wifi_ssid
    if [ -f $ETCDIR/wifi_credentials ]; then
	echo -n "Wifi credentials: "
	cat $ETCDIR/wifi_credentials
    fi
    # XXX actually configure wifi
fi
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Check for NTP config"
if [ -f $ETCDIR/ntp-server ]; then
    echo -n "Using "
    cat $ETCDIR/ntp-server
    # XXX is ntp service running/installed?
    # XXX actually configure ntp
    # Ubuntu has /usr/bin/timedatectl; ditto Debian
    # ntpdate pool.ntp.org
    # Not installed on Ubuntu
    #
    if [ -f /usr/bin/ntpdate ]; then
	/usr/bin/ntpdate `cat $ETCDIR/ntp-server`
    elif [ -f /usr/bin/timedatectl ]; then
	echo "NTP might already be running. Check"
	/usr/bin/timedatectl status
    else
	echo "NTP not installed. Giving up"
	exit 1
    fi
fi
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

if [ $SELF_REGISTER = 1 ]; then
    echo "Self-registering our device certificate"
    if [ ! \( -f $ETCDIR/onboard.cert.pem -a -f $ETCDIR/onboard.key.pem \) ]; then
	echo "Missing provisioning certificate. Giving up"
	exit 1
    fi
    $BINDIR/client $ETCDIR selfRegister
    if [ $WAIT == 1 ]; then
	echo; read -n 1 -s -p "Press any key to continue"; echo; echo
    fi
fi

# XXX should we redo this? Also want zedserverconfig updated
if [ ! -f $ETCDIR/lisp.config ]; then
    echo "Retrieving device and overlay network config"
    $BINDIR/client $ETCDIR lookupParam
    echo "Retrieved overlay /etc/hosts with:"
    cat $ETCDIR/zedserverconfig
    # edit zedserverconfig into /etc/hosts
    match=`awk '{print $2}' $ETCDIR/zedserverconfig| sort -u | awk 'BEGIN {m=""} { m = sprintf("%s|%s", m, $1) } END { m = substr(m, 2, length(m)); printf ".*:.*(%s)\n", m}'`
    egrep -v $match /etc/hosts >/tmp/hosts.$$
    cat $ETCDIR/zedserverconfig >>/tmp/hosts.$$
    echo "New /etc/hosts:"
    cat /tmp/hosts.$$
    sudo cp /tmp/hosts.$$ /etc/hosts
    rm -f /tmp/hosts.$$
    if [ $WAIT == 1 ]; then
	echo; read -n 1 -s -p "Press any key to continue"; echo; echo
    fi
fi

echo "Starting overlay network"
if [ ! -d /usr/local/bin/lisp ]; then
    echo "Missing /usr/local/bin/lisp directory. Giving up"
    exit 1
fi
    
cd /usr/local/bin/lisp
./STOP-LISP
cp ../../etc/zededa/lisp.config .
diff /usr/local/etc/zededa/lisp.config lisp.config
eid=`grep "eid-prefix = fd" lisp.config | awk '{print $3}' | awk -F/ '{print $1}'`
# Mostly gets the right interface
intf=`ip addr show scope global up | grep BROADCAST | awk -F : '{print $2}'`
# Take first from list
first=`echo $intf | awk '{print $1}'`
intf=$first

echo "Starting LISP with EID" $eid "on" $intf

sudo /sbin/ifconfig lo inet6 add $eid
sudo ip route add 0::/0 via fe80::1 dev $intf
sudo ip nei add fe80::1 lladdr 0:0:0:0:0:1 dev $intf
sudo ip nei change fe80::1 lladdr 0:0:0:0:0:1 dev $intf
./RESTART-LISP 8080 $intf
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Starting ZedManager"
# Do something
if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Uploading device (hardware) status"
machine=`uname -m`
processor=`uname -p`
platform=`uname -i`
if [ -f /proc/device-tree/compatible ]; then
    compatible=`cat /proc/device-tree/compatible`
else
    compatible=""
fi
memory=`awk '/MemTotal/ {print $2}' /proc/meminfo`
storage=`df -kl --output=size / | tail -n +2| awk '{print $1}'`
cat >$ETCDIR/hwstatus.json <<EOF
{
	"Machine": "$machine",
	"Processor": "$processor",
	"Platform": "$platform",
	"Compatible": "$compatible",
	"Memory": $memory,
	"Storage": $storage
}
EOF
$BINDIR/client $ETCDIR updateHwStatus

if [ $WAIT == 1 ]; then
    echo; read -n 1 -s -p "Press any key to continue"; echo; echo
fi

echo "Uploading software status"
# Only report the Linux info for now
name=`uname -o`
version=`uname -r`
description=`uname -v`
cat >$ETCDIR/swstatus.json <<EOF
{
	"ApplicationStatus": [
		{
			"EID": "::",
			"Name": "$name",
			"Version": "$version",
			"Description": "$description",
			"State": 5,
			"Activated": true
		}
	]
}
EOF
$BINDIR/client $ETCDIR updateSwStatus

echo "Initial setup done!"


