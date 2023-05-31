#!/bin/sh
#
# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#

##
# go compatible versions
lastSemver=$(git --no-pager describe --match='v[0-9].[0-9].[0-9]*' --abbrev=0 --tags 2>/dev/null || echo "v0.0.0")
commitList="HEAD"
if [ "$lastSemver" != "v0.0.0" ]; then
        commitList="${lastSemver}..HEAD"
fi
count=$(git rev-list "${commitList}" --count)
version=""

if [ "$count" = "0" ]; then
        version="${lastSemver}"
else
        dateCommit=$(git --no-pager show --quiet --abbrev=12 --date="format-local:%Y%m%d%H%M%S" --format="%cd-%h")
        version="${lastSemver}-${dateCommit}"
fi

echo "${version}"