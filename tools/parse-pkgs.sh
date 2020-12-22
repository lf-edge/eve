#!/bin/bash
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.
#
EVE="$(cd "$(dirname "$0")" && pwd)/../"
PATH="$EVE/build-tools/bin:$PATH"

get_git_tag() {
  echo ${EVE_HASH:-$(git tag -l --points-at HEAD | grep '[0-9]*\.[0-9]*\.[0-9]*' | head -1)}
}

linuxkit_tag() {
    echo "$(linuxkit pkg show-tag ${EVE_HASH:+--hash $EVE_HASH} "$EVE/$1")$ARCH"
}

immutable_tag() {
  # we have to resolve symbolic tags like x.y.z or snapshot to something immutable
  # so that we can detect when the symbolic tag starts pointing a different immutable
  # object and thus trigger a new SHA for things like EVE
  echo $(docker inspect --format='{{.Id}}' "$1" 2>/dev/null ||
         docker inspect --format='{{index .RepoDigests 0}}' "$1" 2>/dev/null ||
         echo "$1")
}

external_tag() {
  # Since the tag is external to us, we can't rely on local git SHAs,
  # thus the best we can do is:
  #    1. if we're building a release from a tag, we expect external tag to be the same
  #    2. if we're NOT building from a tag, the external tag is simply snapshot
  local TAG="`get_git_tag`"
  PKG="$1:${TAG:-snapshot}${ARCH}"

  # for external packages we have to always try to pull first - otherwise
  # we may have something stale in our local Docker cache
  docker pull "$PKG" 2>/dev/null >&2 || echo "WARNING: couldn't fetch the latest $PKG - may be using stale cache" >&2
  if docker inspect "$PKG" >/dev/null 2>&1 ; then
    echo "$PKG"
  else
    echo "WARNING: failed to obtain $PKG - using $2 instead" >&2
    echo $2
  fi
}

synthetic_tag() {
  NAME=$1
  shift 1
  echo ${NAME}:${EVE_HASH:-$( (cat "$@" ; git rev-parse HEAD) | resolve_tags | git hash-object --stdin)}"$ARCH"
}

resolve_tags() {
sed -e '/-.*linuxkit\/.*:/s# *$#'${ARCH}# \
    -e '/image:.*linuxkit\/.*:/s# *$#'${ARCH}# \
    -e "s#CURDIR#$(pwd)#" \
    -e "s#ACRN_KERNEL_TAG#$ACRN_KERNEL_TAG#" \
    -e "s#NEW_KERNEL_TAG#$NEW_KERNEL_TAG#" \
    -e "s#KERNEL_TAG#$KERNEL_TAG#" \
    -e "s#FW_TAG#$FW_TAG#" \
    -e "s#XENTOOLS_TAG#$XENTOOLS_TAG#" \
    -e "s#DOM0ZTOOLS_TAG#$DOM0ZTOOLS_TAG#" \
    -e "s#RNGD_TAG#$RNGD_TAG#" \
    -e "s#XEN_TAG#$XEN_TAG#" \
    -e "s#ACRN_TAG#$ACRN_TAG#" \
    -e "s#DNSMASQ_TAG#$DNSMASQ_TAG#" \
    -e "s#STRONGSWAN_TAG#$STRONGSWAN_TAG#" \
    -e "s#TESTCERT_TAG#$TESTCERT_TAG#" \
    -e "s#TESTMSVCS_TAG#$TESTMSVCS_TAG#" \
    -e "s#PILLAR_TAG#$PILLAR_TAG#" \
    -e "s#STORAGE_INIT_TAG#$STORAGE_INIT_TAG#" \
    -e "s#QREXECLIB_TAG#$QREXECLIB_TAG#" \
    -e "s#WWAN_TAG#$WWAN_TAG#" \
    -e "s#WLAN_TAG#$WLAN_TAG#" \
    -e "s#GUACD_TAG#$GUACD_TAG#" \
    -e "s#GRUB_TAG#$GRUB_TAG#" \
    -e "s#DTREES_TAG#$DTREES_TAG#" \
    -e "s#GPTTOOLS_TAG#$GPTTOOLS_TAG#" \
    -e "s#NEWLOGD_TAG#$NEWLOGD_TAG#" \
    -e "s#WATCHDOG_TAG#$WATCHDOG_TAG#" \
    -e "s#MKRAW_TAG#$MKRAW_TAG#" \
    -e "s#MKISO_TAG#$MKISO_TAG#" \
    -e "s#MKCONF_TAG#$MKCONF_TAG#" \
    -e "s#DEBUG_TAG#$DEBUG_TAG#" \
    -e "s#LISP_TAG#$LISP_TAG#" \
    -e "s#VTPM_TAG#${VTPM_TAG}#" \
    -e "s#UEFI_TAG#${UEFI_TAG}#" \
    -e "s#EVE_TAG#${EVE_TAG}#" \
    -e "s#KVMTOOLS_TAG#${KVMTOOLS_TAG}#" \
    -e "s#SPDK_TAG#${SPDK_TAG}#" \
    ${1:-}
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

KERNEL_TAG=$(linuxkit_tag pkg/kernel)
NEW_KERNEL_TAG=$(linuxkit_tag pkg/new-kernel)
ACRN_KERNEL_TAG=$(linuxkit_tag pkg/acrn-kernel)
FW_TAG=$(linuxkit_tag pkg/fw)
XENTOOLS_TAG=$(linuxkit_tag pkg/xen-tools)
XEN_TAG=$(linuxkit_tag pkg/xen)
ACRN_TAG=$(linuxkit_tag pkg/acrn)
GRUB_TAG=$(linuxkit_tag pkg/grub)
DNSMASQ_TAG=$(linuxkit_tag pkg/dnsmasq)
STRONGSWAN_TAG=$(linuxkit_tag pkg/strongswan)
TESTMSVCS_TAG=$(linuxkit_tag pkg/test-microsvcs)
DOM0ZTOOLS_TAG=$(linuxkit_tag pkg/dom0-ztools)
RNGD_TAG=$(linuxkit_tag pkg/rngd)
QREXECLIB_TAG=$(linuxkit_tag pkg/qrexec-lib)
NEWLOGD_TAG=$(linuxkit_tag pkg/newlog)
WWAN_TAG=$(linuxkit_tag pkg/wwan)
WLAN_TAG=$(linuxkit_tag pkg/wlan)
GUACD_TAG=$(linuxkit_tag pkg/guacd)
LISP_TAG=$(linuxkit_tag pkg/lisp)
PILLAR_TAG=$(linuxkit_tag pkg/pillar)
STORAGE_INIT_TAG=$(linuxkit_tag pkg/storage-init)
GPTTOOLS_TAG=$(linuxkit_tag pkg/gpt-tools)
WATCHDOG_TAG=$(linuxkit_tag pkg/watchdog)
MKRAW_TAG=$(linuxkit_tag pkg/mkimage-raw-efi)
MKISO_TAG=$(linuxkit_tag pkg/mkimage-iso-efi)
MKCONF_TAG=$(linuxkit_tag pkg/mkconf)
DEBUG_TAG=$(linuxkit_tag pkg/debug)
VTPM_TAG=$(linuxkit_tag pkg/vtpm)
UEFI_TAG=$(linuxkit_tag pkg/uefi)
KVMTOOLS_TAG=$(linuxkit_tag pkg/kvm-tools)
SPDK_TAG=$(linuxkit_tag pkg/spdk)

# Synthetic tags: the following tags are based on hashing
# the contents of all the Dockerfile.in that we can find.
# That way, these tags are guaranteed to change whenever
# *any* *single* dependency changes.
#
# These tags need to be declared last sine they depend
# on the previous tags being already defined.
EVE_TAG=$(synthetic_tag zededa/eve pkg/pillar/Dockerfile.in)

resolve_tags $1
