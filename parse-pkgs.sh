#!/bin/sh
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.
#

get_git_tag() {
  git tag -l --points-at HEAD | grep '[0-9]*\.[0-9]*\.[0-9]*' | head -1
}

zenbuild_version() {
  local vers="`get_git_tag`"

  if [ -z "$vers" ] ; then
    vers="0.0.0-`git rev-parse --abbrev-ref HEAD`-`git describe --match v --abbrev=8 --always --dirty`-`date -u +"%Y-%m-%d.%H.%M"`"
    vers=`echo ${vers} | sed -e 's#-master##'`
  fi

  echo $vers
}

linuxkit_tag() {
    linuxkit pkg show-tag $1
}

external_tag() {
  # Since the tag is external to us, we can't rely on local git SHAs,
  # thus the best we can do is:
  #    1. if we're building a release from a tag, we expect external tag to be the same
  #    2. if we're NOT building from a tag, the external tag is simply snapshot
  local TAG="`get_git_tag`"
  TAG="$1:${TAG:-snapshot}"
  
  if (docker inspect "$TAG" || docker pull "$TAG") > /dev/null 2>&1 ; then
    echo "${TAG}"
  else
    echo "WARNING: couldn't fetch $TAG plugin - using $2 instead" >&2
    echo $2
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

# External tags: the following tags will default to
# 'scratch' Docker container if not available.
# This is intended to make plugging extensions into
# our build easier. WARNING: it also means if you're
# not logged into the Docker hub you may see final
# images lacking functionality.
ZTOOLS_TAG=${ZTOOLS_TAG:-$(external_tag zededa/ztools $(linuxkit_tag pkg/debug))}$ARCH
LISP_TAG=${LISP_TAG:-$(external_tag zededa/lisp $(external_tag zededa/zisp scratch 2>/dev/null))}$ARCH

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
    -e "s#LISP_TAG#"$LISP_TAG"#" \
    $1
