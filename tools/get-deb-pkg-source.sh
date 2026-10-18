#!/bin/bash
#
# Copyright (c) 2026 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Download the Ubuntu source packages behind the .deb packages installed in
# EVE: every dpkg status record found (/var/lib/dpkg/status of each container,
# plus the status.d records of packages built from source, which are reported
# but have no Ubuntu source) is resolved to its source package and version,
# and that exact source is fetched from the Ubuntu snapshot the image was
# built from. The snapshot URL is taken from /etc/apt/sources.list.upstream,
# which pkg/ubuntu leaves in every container, unless -m overrides it.
#
# Can be invoked in three different forms:
# 1. Using a single EVE version e.g.,
#    get-deb-pkg-source.sh -s /tmp/sources -u urls 9.7.0-kvm-amd64
# 2. Specify one or more tags using -t <tag> e.g.,
#    get-deb-pkg-source.sh -t lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
# 3. Specify a directory where EVE has been extracted using -e <evedir> e.g,
#    get-deb-pkg-source.sh -s /tmp/sources -u urls -e .
#
# With -u <urlfile> it dumps the source package URLs into the file
# With -s <srcdir> it dumps all the source in that directory
# With -p <prefix> the sources go to <srcdir>/<prefix> and the manifest lines
#    printed on stdout (prefix,source@version,version,path) start with it;
#    defaults to debian
# With -m <url> use that snapshot base URL (https://snapshot.ubuntu.com/ubuntu/<timestamp>)
#
# PARALLEL_JOBS in the environment caps how many sources are fetched at the
# same time (default 8).

set -e

PARALLEL_JOBS=${PARALLEL_JOBS:-8}
POCKETS="resolute resolute-updates resolute-security"
COMPONENTS="main restricted universe multiverse"

verbose=
tags=
evedir=
urlfile=
outdir=/tmp/$$
prefix=debian
snapshot=
while getopts e:vt:u:s:p:m:q o
do      case "$o" in
        v)      verbose=1;;
        q)      ;;
        e)      evedir="$OPTARG";;
        t)      tags="$tags $OPTARG";;
        s)      outdir=$OPTARG;;
        u)      urlfile=$OPTARG;;
        p)      prefix=$OPTARG;;
        m)      snapshot=$OPTARG;;
        [?])    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-p <prefix>] [-m <snapshot url>] [<version>]"
                exit 1;;
        esac
done
shift $((OPTIND-1))

if [ $# == 0 ] && [ -z "$tags" ] && [ -z "$evedir" ]; then
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-p <prefix>] [-m <snapshot url>] [<version>]"
    exit 1
fi

log() { [ -n "$verbose" ] && >&2 echo "$@"; return 0; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/roots"

# --- collect the dpkg databases and the apt sources of every container ---

# copies var/lib/dpkg and etc/apt out of an extracted rootfs tree
collect_tree() {
    tree="$1"; name="$2"
    find "$tree" \( -path '*/var/lib/dpkg/status' -o -path '*/var/lib/dpkg/status.d/*' -o -path '*/etc/apt/sources.list.upstream' \) -type f 2>/dev/null \
        | while read -r f; do
            rel=${f#"$tree"}
            mkdir -p "$work/roots/$name/$(dirname "$rel")"
            cp "$f" "$work/roots/$name/$rel"
          done
}

if [ -n "$evedir" ]; then
    collect_tree "$evedir" evedir
fi
n=0
for TAG in $tags; do
    log "retrieving dpkg databases for $TAG"
    n=$((n+1))
    cid=$(docker create "$TAG")
    mkdir -p "$work/tag$n"
    docker export "$cid" | tar -x -C "$work/tag$n" --wildcards '*var/lib/dpkg/status' '*var/lib/dpkg/status.d/*' '*etc/apt/sources.list.upstream' 2>/dev/null || true
    docker rm "$cid" >/dev/null
    collect_tree "$work/tag$n" "tag$n"
done
for VERSION in "$@"; do
    log "retrieving dpkg databases for EVE $VERSION"
    mkdir -p "$work/eve"
    docker run --rm --entrypoint=sh "lfedge/eve:$VERSION" -c \
        "unsquashfs -d /newroot /bits/rootfs.img >/dev/null && cd /newroot && find . \( -path '*/var/lib/dpkg/status' -o -path '*/var/lib/dpkg/status.d/*' -o -path '*/etc/apt/sources.list.upstream' \) -type f -print0 | tar -c --null -T -" \
        | tar -x -C "$work/eve"
    collect_tree "$work/eve" eve
done

if [ -z "$snapshot" ]; then
    f=$(find "$work/roots" -name sources.list.upstream | head -1)
    [ -n "$f" ] || { >&2 echo "no /etc/apt/sources.list.upstream found; pass the snapshot URL with -m"; exit 1; }
    snapshot=$(awk '$1=="deb"{print $2; exit}' "$f")
fi
log "snapshot: $snapshot"

# --- the source package of every binary package: "source version" ---

find "$work/roots" \( -name status -o -path '*/status.d/*' \) -type f -exec cat {} + 2>/dev/null \
    | awk 'BEGIN { RS = ""; FS = "\n" }
      {
          pkg = ""; ver = ""; src = ""; srcver = ""
          for (i = 1; i <= NF; i++) {
              if ($i ~ /^Package: /) pkg = substr($i, 10)
              else if ($i ~ /^Version: /) ver = substr($i, 10)
              else if ($i ~ /^Source: /) {
                  src = substr($i, 9)
                  if (match(src, / \(.*\)$/)) {
                      srcver = substr(src, RSTART + 2, RLENGTH - 3)
                      src = substr(src, 1, RSTART - 1)
                  }
              }
          }
          if (pkg == "") next
          if (src == "") src = pkg
          if (srcver == "") srcver = ver
          print src, srcver
      }' | sort -u > "$work/wanted"
log "$(wc -l < "$work/wanted") source packages wanted"

# --- the Sources indexes of the snapshot: directory and files of each source ---

: > "$work/sources"
for pocket in $POCKETS; do
    for comp in $COMPONENTS; do
        url="$snapshot/dists/$pocket/$comp/source/Sources.gz"
        log "fetching $url"
        curl -fsSL --retry 5 --retry-delay 5 "$url" | gzip -dc >> "$work/sources" || >&2 echo "WARNING: could not fetch $url"
        echo >> "$work/sources"
    done
done

# "source version directory sha256 size file" per file of the wanted sources
# (the wanted list is read line by line before paragraph mode is switched on)
awk -v wantfile="$work/wanted" 'BEGIN { while ((getline w < wantfile) > 0) want[w] = 1; RS = ""; FS = "\n" }
     {
         pkg = ""; ver = ""; dir = ""; insha = 0; files = ""
         for (i = 1; i <= NF; i++) {
             if ($i ~ /^Package: /) { pkg = substr($i, 10); insha = 0 }
             else if ($i ~ /^Version: /) { ver = substr($i, 10); insha = 0 }
             else if ($i ~ /^Directory: /) { dir = substr($i, 12); insha = 0 }
             else if ($i ~ /^Checksums-Sha256:/) insha = 1
             else if ($i ~ /^ / && insha) files = files $i "\n"
             else insha = 0
         }
         if ((pkg " " ver) in want && dir != "") {
             n = split(files, lines, "\n")
             for (j = 1; j <= n; j++) if (lines[j] != "") {
                 split(lines[j], parts, " ")
                 print pkg, ver, dir, parts[1], parts[2], parts[3]
             }
         }
     }' "$work/sources" | sort -u > "$work/files"

# sources the archive does not know: built from source by a Dockerfile
# (register-sbom-pkg.sh), or a version the snapshot never carried
awk 'NR == FNR { have[$1 " " $2] = 1; next } !(($1 " " $2) in have)' "$work/files" "$work/wanted" > "$work/missing"
if [ -s "$work/missing" ]; then
    log "not in the archive (built from source, see the Dockerfiles):"
    [ -n "$verbose" ] && sed 's/^/  /' "$work/missing" >&2
fi

# --- download ---

if [ -n "$urlfile" ]; then
    awk '{print $1, $2, "'"$snapshot"'/" $3}' "$work/files" | sort -u > "$urlfile"
fi

mkdir -p "$outdir/$prefix"
fetch_one() {
    src="$1"; ver="$2"; dir="$3"; sha="$4"; file="$6"
    dst="$outdir/$prefix/$src.$ver"
    mkdir -p "$dst"
    if [ -f "$dst/$file" ] && echo "$sha  $dst/$file" | sha256sum -c --status; then
        return 0
    fi
    if ! curl -fsSL --retry 5 --retry-delay 5 -o "$dst/$file" "$snapshot/$dir/$file" \
       || ! echo "$sha  $dst/$file" | sha256sum -c --status; then
        >&2 echo "ERROR: failed to download $snapshot/$dir/$file"
        rm -f "$dst/$file"
        return 1
    fi
}
export -f fetch_one
export outdir prefix snapshot
xargs -P "$PARALLEL_JOBS" -n 6 bash -c 'fetch_one "$@"' _ < "$work/files"

# --- manifest: prefix,source@version,version,path ---
awk '{print $1 "." $2, $1 "@" $2, $2}' "$work/files" | sort -u \
    | while read -r dir nv ver; do
        [ -d "$outdir/$prefix/$dir" ] && echo "$prefix,$nv,$ver,$prefix/$dir"
      done
