#!/bin/bash
#
# Copyright (c) 2021 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0
#
# Download source URLs and/or complete source from Alpine including
# the referenced urls in APKBUILD and the patches in APKBUILD itself.
#
# Can be invoked in three different forms:
# 1. Using a single EVE version e.g.,
#    get-alpine-pkg-source.sh -s /tmp/sources -u urls 9.7.0-kvm-amd64
# 2. Specify one or more tags using -t <tag> e.g.,
#    get-alpine-pkg-source.sh -t lfedge/eve-pillar:17837a9fcd05c765e9a1f6707b2e48f0f1dd215b-amd64
# 3. Specify a directory where EVE has been extracted using -e <evedir> e.g,
#    get-alpine-pkg-source.sh -s /tmp/sources -u urls -e .
#
# With -u <urlfile> it dumps the source URL + licenses into the file
# With -s <srcdir> it dumps all the source in that directory
# With -g <gitdir> use the directory as a pre-cloned repo for git.alpinelinux.org instead of cloning it

set -e

verbose=
tags=
evedir=
urlfile=
gitdir=
outdir=/tmp/$$
quiet=
while getopts e:vt:u:s:g:q o
do      case "$o" in
        v)      verbose=1;;
        q)      quiet=1;;
        e)      evedir="$OPTARG";;
        t)      tags="$tags $OPTARG";;
        s)      outdir=$OPTARG;;
        u)      urlfile=$OPTARG;;
        g)      gitdir=$OPTARG;;
        [?])    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-g <gitdir>] [<version>]"
                exit 1;;
        esac
done
shift $((OPTIND-1))


if [ $# == 0 ] && [ -z "$tags" ] && [ -z "$evedir" ]; then
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [<version>]"
    exit 1
fi
if [ $# -gt 1 ]; then
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [<version>]"
    exit 1
fi

if [ -d "$outdir" ]; then
    >&2 echo "outdir $outdir already exists"
    exit 1
fi

if [ -n "$gitdir" ] && [ ! -d "$gitdir" ]; then
    >&2 echo "gitdir $gitdir does not exist"
    exit 1
fi


startdir=$(pwd)
mkdir -p "$outdir"
# ensure absolute path for outdir
outdir=$(readlink -f "${outdir}")
cd "$outdir" || exit 2

[ -n "$verbose" ] && echo "outdir: $outdir"

# Collect all package origin and commit pairs in this file
OCPAIRS=/tmp/ocpairs.$$

# get_ocpairs <installed file> <ocpair output file>
get_ocpairs() {
    # Get pairs of origin and commit. Assumes commit is after origin
    # otherwise we produce XXX output string
    # Filter out duplicates
    awk -F: '
        /^o:/ { origin=$2 }
        /^L:/ { license=$2 }
        /^V:/ { version=$2 }
        /^c:/ { commit=$2 }
        /^\s*$/ {
            if (origin != "") {
                if (commit ~ /^\s*$/) { commit="unknown" };
                print origin, version, commit, license;
                origin=""; license=""; version=""; commit="unknown";
            }
        }' | sort -u
}

if [ $# == 1 ]; then
    VERSION=$1
    tags="lfedge/eve:${VERSION}"
fi


if [ -n "$evedir" ]; then
    find "$evedir" -wholename '*lib/apk/db/installed' -exec cat {} \; | get_ocpairs > ${OCPAIRS}
else
    # for multiple tags, it is easier to handle them one by one and then merge, so we don't miss any CR/LF breaks
    tmppairs=${OCPAIRS}.tmp
    for TAG in ${tags}; do
        [ -n "$verbose" ] && echo "retrieving installed databases for $TAG"
        docker run --rm --entrypoint=sh "${TAG}" -c "unsquashfs -d /newroot /bits/rootfs.img >/dev/null && find /newroot -wholename '*lib/apk/db/installed' -exec cat {} \;" | get_ocpairs >> "${tmppairs}"
        echo >> ${tmppairs}
    done
    cat ${tmppairs} | sort -u > ${OCPAIRS}
fi


# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages times licenses"
# skip licenses
mv ${OCPAIRS} ${OCPAIRS}.with_licenses
awk '{print $1, $2, $3}' ${OCPAIRS}.with_licenses | sort -u >${OCPAIRS}
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages"

badfilescount=0
badfileslist=""

TMP_DIR=$(mktemp -d)
if [ -n "$gitdir" ]; then
    cp -r "$gitdir/." "${TMP_DIR}"
else
    pkgurl="https://git.alpinelinux.org/aports.git"
    git clone "${pkgurl}" "${TMP_DIR}" >/dev/null
fi

# shellcheck disable=SC2002
while read -r line ; do
    # shellcheck disable=SC2086
    set -- $line
    [ $# -lt 3 ] && continue
    origin=$1
    version=$2
    commit=$3
    shift 3
    license="$*"
    # The commit is empty in one case... That is from the eve-debug container
    # Could ignore
    if [ "${commit}" = "unknown" ]; then
        echo "Ignoring ${origin} with empty commit; from eve-debug package"
        continue
    fi
    commitstr="?id=${commit}"

    # Include commit in directory to handle different versions
    pkgpath="${origin}.${version}.${commit}"
    dstdir="${outdir}/${pkgpath}"
    [ -n "$verbose" ] && echo "origin: ${origin} commit: ${commit} dstdir: ${dstdir}"
    # Need to handle main, community and testing repos
    foundRepo=""
    for repo in main community testing; do
            echo "Trying ${origin} in ${repo} at commit ${commit}"
            git -C "${TMP_DIR}" checkout "${commit}" >/dev/null
            sourceDir="${TMP_DIR}/${repo}/${origin}"
            if [ ! -d "${sourceDir}" ]; then
                echo "${origin} not in ${repo} at commit ${commit}"
                continue
            fi
            if [ ! -f "${sourceDir}"/APKBUILD ]; then
                echo "${origin} in ${repo} missing APKBUILD"
                continue
            fi
            cp -r "${sourceDir}/." "${dstdir}/"
            foundRepo="${repo}"

            break
    done
    if [ -z "${foundRepo}" ]; then
        >&2 echo "Failed to find ${origin} at ${commit}"
        exit 2
    fi
    [ -n "$verbose" ] && echo "Retrieved ${origin} ${commit}"
    if [ -n "$urlfile" ]; then
        pkgurl="https://git.alpinelinux.org/aports/plain/${foundRepo}/${origin}/APKBUILD${commitstr}"
        echo "$origin $pkgurl $license" >>"${urlfile}"
    fi
    # XXX is this dangerous? subshell?
    # Start empty
    source=
    sha512sums=
    # shellcheck disable=SC1090,SC1091
    source "${dstdir}/APKBUILD"
    # shellcheck disable=SC2154
    [ -n "$verbose" ] && echo "source: ${source}"
    # shellcheck disable=SC2154
    if [ -n "${sha512sums}" ]; then
        echo "${sha512sums}" > "${dstdir}/sha512sums.APKBUILD"
    fi
    for s in ${source}; do
        url="$s"
        filename=$(basename "${url}")
        # Do we need to split on "::"?
        if echo "$s" | grep -sq "::"; then
            # shellcheck disable=SC2001
            filename="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\1/')"
            # shellcheck disable=SC2001
            url="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\2/')"
        fi
        case $url in
            https://*|http://*|ftp://*)
                [ -n "$verbose" ] && echo "found $s basename ${filename}"
                if ! curl -sSLo "${dstdir}/${filename}" "${url}"; then
                    >&2 echo "Failed to download $url"
                    rm -f "${dstdir}/${filename}"
                    badfileslist="${badfileslist} missing:${pkgpath}:${filename}"
                    badfilescount=$((badfilescount + 1))
                    continue
                fi
                ;;
            *)
                [ -n "$verbose" ] && echo "not http*: $s"
                if [ ! -f "${dstdir}/${filename}" ]; then
                    >&2 echo "Missing file ${filename} $url"
                    badfileslist="${badfileslist} missing:${pkgpath}:${filename}"
                    badfilescount=$((badfilescount + 1))
                    continue
                fi
                ;;
        esac
        if [ -n "${sha512sums}" ]; then
            sum=$(openssl sha512 "${dstdir}/${filename}" | awk '{print $2}')
            rsum=$(grep ' '"$filename"\$ "${dstdir}/sha512sums.APKBUILD" | awk '{print $1}')
            if [ "${sum}" != "${rsum}" ]; then
                errmsg="mismatched-sh512"
                echo "Mismatched sh512 for $url into ${dstdir}/${filename}"
                if grep -qsi '404 Not Found' "${dstdir}/${filename}"; then
                    errmsg="404-not-found"
                    >&2 echo "404 Not Found for ${url}"
                    rm -f "${dstdir}/${filename}"
                elif grep -qsi '^<!DOCTYPE html' "${dstdir}/${filename}"; then
                    >&2 echo "Bad DOCTYPE for $url into ${dstdir}/${filename}"
                    errmsg="bad-content"
                    rm -f "${dstdir}/${filename}"
                elif grep -qsi 'Too many requests' "${dstdir}/${filename}"; then
                    errmsg="too-many-requests"
                    >&2 echo "Too many requests for ${url}"
                    rm -f "${dstdir}/${filename}"
                else
                    [ -n "$verbose" ] && echo "Bad content: $(cat "${dstdir}/${filename}")"
                fi
                # "Bad content" and "Too many requests" isn't really missing ...
                badfileslist="${badfileslist} ${errmsg}:${pkgpath}:${filename}"
                badfilescount=$((badfilescount + 1))
            else
                echo "$sum $filename" >> "${dstdir}/sha512sums.received"
            fi
        fi
    done
    if [ "$badfilescount" != 0 ]; then
        echo "Missing/bad $badfilescount files"
    fi
done < "${OCPAIRS}"

# clean up our temporary cloned directory
rm -rf "$TMP_DIR"
sync

if [ -n "$urlfile" ]; then
    # shellcheck disable=SC2002
    [ -z "$quiet" ] && echo "Saved $(cat "$urlfile" |wc -l) URLs in $urlfile"
fi
cd "$startdir" || exit
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "Collected $(du -sm "$outdir" | cut -f 1) Mbytes for $(cat "${OCPAIRS}" | wc -l) packages of source in $outdir"

# any errors?
if [ -n "$badfileslist" ]; then
    echo "Missing/bad $badfilescount files"
    for b in $badfileslist; do
        echo "  $b"
    done
fi
