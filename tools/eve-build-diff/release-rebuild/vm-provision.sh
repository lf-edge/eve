#!/bin/bash
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Runs inside a fresh Ubuntu VM: installs the docs/BUILD.md prerequisites and
# Go (make builds linuxkit from source), and adds the default user to the
# docker group. The VM must be restarted afterwards for the group to apply.
#   vm-provision.sh <go version, e.g. 1.25.11>
set -euo pipefail
GO=go$1.linux-$(dpkg --print-architecture).tar.gz
sudo apt-get update -q
sudo DEBIAN_FRONTEND=noninteractive apt-get install -yq docker.io docker-buildx make git jq curl
sudo usermod -aG docker "$(id -un)"
curl -fsSLo "/tmp/$GO" "https://go.dev/dl/$GO"
want=$(curl -fsSL 'https://go.dev/dl/?mode=json&include=all' |
       jq -r --arg f "$GO" '.[].files[] | select(.filename == $f) | .sha256')
[ -n "$want" ] || { echo "no checksum published for $GO" >&2; exit 1; }
echo "$want  /tmp/$GO" | sha256sum -c -
sudo tar -C /usr/local -xzf "/tmp/$GO"
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
go version
