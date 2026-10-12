#!/bin/sh
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

# Prints a short content hash used as the Docker image tag of an evetest
# component, so a tag changes exactly when the component's sources change:
#
#   framework  everything baked into the lfedge/evetest and
#              lfedge/evetest-broker images
#   sdn        everything baked into the lfedge/evetest-sdn image
#
# The hash covers the working-tree content (committed, modified and untracked
# but not git-ignored files), not commit ids, so it is the same after a
# rebase or a squash and reflects uncommitted edits.

set -eu

cd "$(dirname "$0")"

case "${1:-}" in
framework)
    # tests/, netmodels/ and matchers/ are bind-mounted at run time and
    # testapps/ images are built separately. The SDN image has its own hash,
    # and the submodule is not baked in (generated Go code is committed).
    set -- . \
        ':(exclude)tests' ':(exclude)netmodels' ':(exclude)matchers' \
        ':(exclude)testapps' ':(exclude)sdn' ':(exclude)deploy' \
        ':(exclude)grpcapi/eve-api' ':(exclude,glob)**/*.md'
    ;;
sdn)
    set -- sdn ':(exclude)sdn/pics' ':(exclude,glob)**/*.md'
    ;;
*)
    echo "usage: $0 framework|sdn" >&2
    exit 2
    ;;
esac

# The single-quoted script is meant to be expanded by the inner sh, not here.
# shellcheck disable=SC2016
git ls-files -z --cached --others --exclude-standard -- "$@" |
    LC_ALL=C sort -z |
    xargs -0 sh -c 'for f; do if [ -f "$f" ]; then sha256sum "$f"; fi; done' sh |
    sha256sum | cut -c1-16
