#!/bin/sh
# in this query-edgeview.sh example script:
# - port mapping is optional for some TCP query options
# - mount of download directory is optional and only for file copy option
# - the query docker container is build with 'make eve-edgeview' in this directory
# - or get the query 'edge-view' container from lfedge/eve-edgeview:latest
# - the 'EDGEVIEW_CLIENT' variable needs to be set since the same docker image also runs on EVE edge-nodes
# shellcheck disable=SC2086,SC2046
docker run -it --rm -e EDGEVIEW_CLIENT=1 -h=$(hostname) -p 9001-9005:9001-9005 -v /tmp/download:/download lfedge/eve-edgeview "$@"
