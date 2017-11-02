#!/bin/bash
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.

ARCH=amd64

KERNEL_TAG=$(./findtag.sh pkg/kernel)-$ARCH
XENTOOLS_TAG=$(./findtag.sh pkg/xen-tools)-$ARCH
XEN_TAG=$(./findtag.sh pkg/xen)-$ARCH
TESTCERT_TAG=$(./findtag.sh pkg/test-cert)-$ARCH
TESTMSVCS_TAG=$(./findtag.sh pkg/test-microsvcs)-$ARCH
ZEDEDA_TAG=$(./findtag.sh zededa-container)-$ARCH

sed -e "s#KERNEL_TAG#"$KERNEL_TAG"#" \
    -e "s#XENTOOLS_TAG#"$XENTOOLS_TAG"#" \
    -e "s#XEN_TAG#"$XEN_TAG"#" \
    -e "s#TESTCERT_TAG#"$TESTCERT_TAG"#" \
    -e "s#TESTMSVCS_TAG#"$TESTMSVCS_TAG"#" \
    -e "s#ZEDEDA_TAG#"$ZEDEDA_TAG"#" \
    $1
