#!/bin/sh
#
# This *really* needs to be replaced with tini+monit ASAP.

# Start with a default content for resolv.conf
echo 'nameserver 8.8.8.8' > /etc/resolv.conf

# Need to disable H/W TCP offload since it seems to mess us up
for i in `cd /sys/class/net ; echo eth*` ; do
  ethtool -K $i gro off
  ethtool -K $i sg off
done

# constructing /run/authorized_keys from a static one
# At some point we may also consider extracting key material
# from x509 certificates...
#   bash -c 'ssh-keygen -f <(openssl x509 -in /config/onboard.cert.pem -pubkey -noout) -i -mPKCS8' >> /run/authorized_keys
# ...or using CA signed ssh keys
#   TrustedUserCAKeys /path/to/server_ca.pub
sed -e '/^[a-z][a-z]*/s#^#command="ctr --namespace services.linuxkit t exec -t --exec-id $(basename $(mktemp)) pillar sh" #' < /config/authorized_keys > /run/authorized_keys
chmod 600 /run/authorized_keys

# Need this for logrotate
/usr/sbin/crond

# Finally, we need to start Xen
XENCONSOLED_ARGS='--log=all --log-dir=/var/log/xen' /etc/init.d/xencommons start

# This is an optional component - only run it if it is there
if [ -f /opt/zededa/bin/device-steps.sh ]; then
    /opt/zededa/bin/device-steps.sh -w >/var/log/device-steps.log 2>&1
fi

tail -f /dev/null /var/log/*.log
