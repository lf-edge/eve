#!/bin/sh
#
# Copyright (c) 2025 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0


# This will setup the directory layout and the required files in kube container.
# We basically copy the /opt/vendor/nvidia/dist directory layout to corresponding directories in kube container.
# nvidia-runtime-binary will load those files while creating containers.

logmsg "Copying nvidia binaries and libraries"
if [ -d "/opt/vendor/nvidia/" ]; then
   cp /opt/vendor/nvidia/bin/* /usr/bin
   cp -R /opt/vendor/nvidia/dist/usr/* /usr
   cp -R /opt/vendor/nvidia/dist/lib/* /lib
   cp -R /opt/vendor/nvidia/dist/etc/* /etc
fi
