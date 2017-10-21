#!/bin/bash
# Poor man's[1] yml generator
#
#
# [1] A poor man is a man on a deadline.

KERNEL_TAG=$(./findtag.sh pkg/kernel)
XENTOOLS_TAG=$(./findtag.sh pkg/xen-tools)
XEN_TAG=$(./findtag.sh pkg/xen)
TESTCERT_TAG=$(./findtag.sh pkg/test-cert)
ZEDEDA_TAG=$(./findtag.sh zededa-container)

sed -e "s#KERNEL_TAG#"$KERNEL_TAG"#" \
    -e "s#XENTOOLS_TAG#"$XENTOOLS_TAG"#" \
    -e "s#XEN_TAG#"$XEN_TAG"#" \
    -e "s#TESTCERT_TAG#"$TESTCERT_TAG"#" \
    -e "s#ZEDEDA_TAG#"$ZEDEDA_TAG"#" \
    $1
