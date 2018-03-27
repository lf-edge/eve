#!/bin/sh
#
# Zeninstaller
#
# Install Ze*ix distribution to a device.
#
# Usage:
#
#   install.sh <device>

echo "STARTING INSTALLATION"
/make-flash $1
echo "INSTALLATION COMPLETE. GOODBYE."
halt

