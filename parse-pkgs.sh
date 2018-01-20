#!/bin/sh
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.
#

linuxkit_tag() {
    linuxkit pkg show-tag $1
}

plugin_tag() {
  if (docker inspect "$1" || docker pull "$1") > /dev/null 2>&1 ; then
    echo $1
  else
    echo "WARNING: couldn't fetch $1 plugin - disabling it in the final build" >&2
    echo scratch
  fi
}

ARCH=amd64

KERNEL_TAG=$(linuxkit_tag pkg/kernel)-$ARCH
XENTOOLS_TAG=$(linuxkit_tag pkg/xen-tools)-$ARCH
XEN_TAG=$(linuxkit_tag pkg/xen)-$ARCH
GRUB_TAG=$(linuxkit_tag pkg/grub)-$ARCH
DNSMASQ_TAG=$(linuxkit_tag pkg/dnsmasq)-$ARCH
TESTCERT_TAG=$(linuxkit_tag pkg/test-cert)-$ARCH
TESTMSVCS_TAG=$(linuxkit_tag pkg/test-microsvcs)-$ARCH
ZEDEDA_TAG=$(linuxkit_tag zededa-container)-$ARCH
DOM0ZTOOLS_TAG=$(linuxkit_tag pkg/dom0-ztools)-$ARCH
QREXECLIB_TAG=$(linuxkit_tag pkg/qrexec-lib)-$ARCH
WWAN_TAG=$(linuxkit_tag pkg/wwan)-$ARCH
WLAN_TAG=$(linuxkit_tag pkg/wlan)-$ARCH

# Plugin tags: the following tags will default to
# 'scratch' Docker container if not available.
# This is intended to make plugging extensions into
# our build easier. WARNING: it also means if you're
# not logged into the Docker hub you may see final
# images lacking functionality.
ZTOOLS_TAG=${ZTOOLS_TAG:-$(plugin_tag zededa/ztools:latest)}

sed -e "s#KERNEL_TAG#"$KERNEL_TAG"#" \
    -e "s#XENTOOLS_TAG#"$XENTOOLS_TAG"#" \
    -e "s#DOM0ZTOOLS_TAG#"$DOM0ZTOOLS_TAG"#" \
    -e "s#XEN_TAG#"$XEN_TAG"#" \
    -e "s#DNSMASQ_TAG#"$DNSMASQ_TAG"#" \
    -e "s#TESTCERT_TAG#"$TESTCERT_TAG"#" \
    -e "s#TESTMSVCS_TAG#"$TESTMSVCS_TAG"#" \
    -e "s#ZEDEDA_TAG#"$ZEDEDA_TAG"#" \
    -e "s#ZTOOLS_TAG#"$ZTOOLS_TAG"#" \
    -e "s#QREXECLIB_TAG#"$QREXECLIB_TAG"#" \
    -e "s#WWAN_TAG#"$WWAN_TAG"#" \
    -e "s#WLAN_TAG#"$WLAN_TAG"#" \
    -e "s#GRUB_TAG#"$GRUB_TAG"#" \
    $1
