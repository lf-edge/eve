#!/usr/bin/env bash
set -e
export CGO_ENABLED=${CGO_ENABLED:-1}
export GO111MODULE=${GO111MODULE:-on}
export CGO_LDFLAGS=${CGO_LDFLAGS:--lm}
export YETUS_OUT=${YETUS_OUT:-/tmp/yetus-out}
apt-get -q update && apt-get -q install --no-install-recommends -y libpcap-dev
