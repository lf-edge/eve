#!/bin/sh
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.
#

zenbuild_version() {
  local vers="`git tag -l --points-at HEAD | grep '[0-9]*\.[0-9]*\.[0-9]*' | head -1`"

  if [ -z "$vers" ] ; then
    vers="0.0.0-`git rev-parse --abbrev-ref HEAD`-`git describe --match v --abbrev=8 --always --dirty`-`date -u +"%Y-%m-%d.%H.%M"`"
    vers=`echo ${vers} | sed -e 's#-master##'`
  fi

  echo $vers
}

linuxkit_tag() {
    linuxkit pkg show-tag $1
}

plugin_tag() {
  if (docker inspect "$1" || docker pull "$1") > /dev/null 2>&1 ; then
    echo $1
  else
    echo "WARNING: couldn't fetch $1 plugin - disabling it in the final build (enabling debugging)" >&2
    echo $(linuxkit_tag pkg/debug)$ARCH
  fi
}

if [ -z "$DOCKER_ARCH_TAG" ] ; then
  case $(uname -m) in
    x86_64) ARCH=-amd64
      ;;
    aarch64) ARCH=-arm64
      ;;
    *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1
      ;;
  esac
else
  ARCH="-${DOCKER_ARCH_TAG}"
fi

ZENBUILD_VERSION=`zenbuild_version`$ARCH

KERNEL_TAG=$(linuxkit_tag pkg/kernel)$ARCH
FW_TAG=$(linuxkit_tag pkg/fw)$ARCH
XENTOOLS_TAG=$(linuxkit_tag pkg/xen-tools)$ARCH
XEN_TAG=$(linuxkit_tag pkg/xen)$ARCH
GRUB_TAG=$(linuxkit_tag pkg/grub)$ARCH
DTREES_TAG=$(linuxkit_tag pkg/device-trees)$ARCH
DNSMASQ_TAG=$(linuxkit_tag pkg/dnsmasq)$ARCH
STRONGSWAN_TAG=$(linuxkit_tag pkg/strongswan)$ARCH
TESTMSVCS_TAG=$(linuxkit_tag pkg/test-microsvcs)$ARCH
ZEDEDA_TAG=$(linuxkit_tag pkg/zedctr)$ARCH
DOM0ZTOOLS_TAG=$(linuxkit_tag pkg/dom0-ztools)$ARCH
RNGD_TAG=$(linuxkit_tag pkg/rngd)$ARCH
QREXECLIB_TAG=$(linuxkit_tag pkg/qrexec-lib)$ARCH
WWAN_TAG=$(linuxkit_tag pkg/wwan)$ARCH
WLAN_TAG=$(linuxkit_tag pkg/wlan)$ARCH
GUACD_TAG=$(linuxkit_tag pkg/guacd)$ARCH
GPTTOOLS_TAG=$(linuxkit_tag pkg/gpt-tools)$ARCH
WATCHDOG_TAG=$(linuxkit_tag pkg/watchdog)$ARCH
MKRAW_TAG=$(linuxkit_tag pkg/mkimage-raw-efi)$ARCH
DEBUG_TAG=$(linuxkit_tag pkg/debug)$ARCH

# Plugin tags: the following tags will default to
# 'scratch' Docker container if not available.
# This is intended to make plugging extensions into
# our build easier. WARNING: it also means if you're
# not logged into the Docker hub you may see final
# images lacking functionality.
ZTOOLS_TAG=${ZTOOLS_TAG:-$(plugin_tag zededa/ztools:latest)}

sed -e '/-.*linuxkit\/.*:/s# *$#'${ARCH}# \
    -e '/image:.*linuxkit\/.*:/s# *$#'${ARCH}# \
    -e "s#ZENBUILD_VERSION#"$ZENBUILD_VERSION"#" \
    -e "s#KERNEL_TAG#"$KERNEL_TAG"#" \
    -e "s#FW_TAG#"$FW_TAG"#" \
    -e "s#XENTOOLS_TAG#"$XENTOOLS_TAG"#" \
    -e "s#DOM0ZTOOLS_TAG#"$DOM0ZTOOLS_TAG"#" \
    -e "s#RNGD_TAG#"$RNGD_TAG"#" \
    -e "s#XEN_TAG#"$XEN_TAG"#" \
    -e "s#DNSMASQ_TAG#"$DNSMASQ_TAG"#" \
    -e "s#STRONGSWAN_TAG#"$STRONGSWAN_TAG"#" \
    -e "s#TESTCERT_TAG#"$TESTCERT_TAG"#" \
    -e "s#TESTMSVCS_TAG#"$TESTMSVCS_TAG"#" \
    -e "s#ZEDEDA_TAG#"$ZEDEDA_TAG"#" \
    -e "s#ZTOOLS_TAG#"$ZTOOLS_TAG"#" \
    -e "s#QREXECLIB_TAG#"$QREXECLIB_TAG"#" \
    -e "s#WWAN_TAG#"$WWAN_TAG"#" \
    -e "s#WLAN_TAG#"$WLAN_TAG"#" \
    -e "s#GUACD_TAG#"$GUACD_TAG"#" \
    -e "s#GRUB_TAG#"$GRUB_TAG"#" \
    -e "s#DTREES_TAG#"$DTREES_TAG"#" \
    -e "s#GPTTOOLS_TAG#"$GPTTOOLS_TAG"#" \
    -e "s#WATCHDOG_TAG#"$WATCHDOG_TAG"#" \
    -e "s#MKRAW_TAG#"$MKRAW_TAG"#" \
    -e "s#DEBUG_TAG#"$DEBUG_TAG"#" \
    $1
