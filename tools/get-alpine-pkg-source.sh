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
# 3. Speify a directory where EVE has been extracted using -e <evedir> e.g,
#    get-alpine-pkg-source.sh -s /tmp/sources -u urls -e .
#
# With -u <urlfile> it dumps the source URL + licenses into the file
# With -s <srcdir> it dumps all the source in that directory
verbose=
tags=
evedir=
urlfile=
outdir=/tmp/$$
quiet=
while getopts e:vt:u:s:q o
do      case "$o" in
        v)      verbose=1;;
        q)      quiet=1;;
        e)      evedir="$OPTARG";;
        t)      tags="$tags $OPTARG";;
        s)      outdir=$OPTARG;;
        u)      urlfile=$OPTARG;;
        [?])    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [<version>]"
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

startdir=$(pwd)
mkdir -p "$outdir"
cd "$outdir" || exit 2

[ -n "$verbose" ] && echo "outdir: $outdir"

if [ $# == 1 ]; then
    VERSION=$1
    [ -n "$verbose" ] && echo "retrieving build_config for $VERSION"
    docker run "lfedge/eve:${VERSION}" build_config >build_config.out
    tags1=$(grep image: build_config.out | awk '{print $2}')
    tags2=$(awk '/^init:/ {pr=1} /^onboot:/ {pr=0} /^-/ {if (pr) {print $2}}' <build_config.out)
    tags="$tags2 $tags1"
fi

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
        /^c:/ { commit=$2; if (commit == "") { commit = "unknown" }; print origin, commit, license; origin="XXX"; license="" }' < "$1" | sort -u > "$2"
}

if [ -n "$evedir" ]; then
    find "$evedir" -wholename '*lib/apk/db/installed' | while read -r installed ; do
        [ -n "$verbose" ] && echo "packages from ${TAG} in ${installed}"
        ocpairs=$(mktemp "${OCPAIRS}.XXXXXX")
        get_ocpairs "${installed}" "${ocpairs}"
        if grep -sq XXX "${ocpairs}"; then
            >&2 echo "Missing package origin in ${installed}"
            exit 2
        fi
    done
else
    for TAG in ${tags}; do
        [ -n "$verbose" ] && echo "processing $TAG"
        installed=$(mktemp "/tmp/installed.$$.XXXXXX")
        ocpairs=$(mktemp "${OCPAIRS}.XXXXXX")
        c=$(docker create "${TAG}" 2>/dev/null)
        if [ -z "$c" ]; then
            # Try bogus command
            c=$(docker create "${TAG}" xxx 2>/dev/null)
        fi
        docker cp "$c":/lib/apk/db/installed "${installed}"
        docker rm "$c" >/dev/null

        # XXX check: Need COPY lib/apk/db /lib/apk/db in Dockerfile for linuxkit/getty etc
        if [ ! -s "${installed}" ]; then
            echo "No /lib/apk/db/installed for ${TAG}"
            continue
        fi

        [ -n "$verbose" ] && echo "packages from ${TAG} in ${installed}"

        get_ocpairs "${installed}" "${ocpairs}"
        if grep -sq XXX "${ocpairs}"; then
            >&2 echo "Missing package origin in ${installed}"
            exit 2
        fi
        # shellcheck disable=SC2002
        [ -n "$verbose" ] && echo "processing $TAG: $(cat "${ocpairs}" | wc -l) packages"
    done
fi

cat ${OCPAIRS}.* | sort -u >${OCPAIRS}

# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages times licenses"
# skip licenses
mv ${OCPAIRS} ${OCPAIRS}.with_licenses
awk '{print $1, $2}' ${OCPAIRS}.with_licenses | sort -u >${OCPAIRS}
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages"

missing=0

# shellcheck disable=SC2002
cat ${OCPAIRS} | while read -r line ; do
    # shellcheck disable=SC2086
    set -- $line
    origin=$1
    commit=$2
    shift 2
    license="$*"
    # The commit is empty in one case... That is from the eve-debug container
    # Could ignore
    if [ "${commit}" = "unknown" ]; then
        echo "Ignoring ${origin} with empty commit; from eve-debug package"
        continue
    fi
    commitstr="?id=${commit}"

    # Include commit in directory to handle different versions
    dstdir="${origin}.${commit}"
    [ -n "$verbose" ] && echo "origin: ${origin} commit: ${commit} dstdir: ${dstdir}"
    mkdir "${dstdir}"
    # Need to handle main, community and testing repos
    for repo in main community testing; do
            pkgurl="https://git.alpinelinux.org/aports/plain/${repo}/${origin}/APKBUILD${commitstr}"
            if ! curl -sSLo "${dstdir}"/APKBUILD "$pkgurl"; then
                echo "Failed to download $pkgurl"
                pkgurl=""
                continue
            fi
            if [ ! -f "${dstdir}"/APKBUILD ]; then
                echo "Failed to fetch ${pkgurl}"
                pkgurl=""
                continue
            fi
            # We do not get a 404 on failure but an html document
            if grep -qsi '^<!DOCTYPE html' "${dstdir}"/APKBUILD; then
                [ -n "$verbose" ] && echo "Fetched html from ${pkgurl}"
                pkgurl=""
                continue
            fi
            break
    done
    if [ -z "${pkgurl}" ]; then
        >&2 echo "Failed to fetch ${origin} ${commit}"
        exit 2
    fi
    [ -n "$verbose" ] && echo "Fetched ${origin} ${commit} from ${pkgurl}"
    if [ -n "$urlfile" ]; then
        echo "$origin $pkgurl $license" >>"${urlfile}"
    fi
    # XXX is this dangerous? subshell?
    # Start empty
    source=
    sha512sums=
    # shellcheck disable=SC1090,SC1091
    source "${dstdir}"/APKBUILD
    # shellcheck disable=SC2154
    [ -n "$verbose" ] && echo "source: ${source}"
    # shellcheck disable=SC2154
    if [ -n "${sha512sums}" ]; then
        echo "${sha512sums}" > "${dstdir}/sha512sums.APKBUILD"
    fi
    for s in ${source}; do
        if echo "$s" | grep -sq "https://"; then
            [ -n "$verbose" ] && echo "found $s basename $(basename "$s")"
            filename="$(basename "$s")"
            url="$s"
            # Do we need to split on "::"?
            if echo "$s" | grep -sq "::"; then
                # shellcheck disable=SC2001
                filename="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\1/')"
                # shellcheck disable=SC2001
                url="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\2/')"
            fi
        elif echo "$s" | grep -sq "http://"; then
            [ -n "$verbose" ] && echo "found $s basename $(basename "$s")"
            filename="$(basename "$s")"
            url="$s"
            # Do we need to split on "::"?
            if echo "$s" | grep -sq "::"; then
                # shellcheck disable=SC2001
                filename="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\1/')"
                # shellcheck disable=SC2001
                url="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\2/')"
            fi
        elif echo "$s" | grep -sq "ftp://"; then
            [ -n "$verbose" ] && echo "found $s basename $(basename "$s")"
            filename="$(basename "$s")"
            url="$s"
            # Do we need to split on "::"?
            if echo "$s" | grep -sq "::"; then
                # shellcheck disable=SC2001
                filename="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\1/')"
                # shellcheck disable=SC2001
                url="$(echo "$s" | sed 's/^\(.*\)::\(.*$\)/\2/')"
            fi
        else
            [ -n "$verbose" ] && echo "not http*: $s"
            filename="$s"
            url="https://git.alpinelinux.org/aports/plain/${repo}/${origin}/${s}${commitstr}"
        fi
        [ -n "$verbose" ] && echo "filename: $filename url: $url"
        if ! curl -sSLo "${dstdir}/${filename}" "${url}"; then
            >&2 echo "Failed to download $url"
            rm -f "${dstdir}/${filename}"
            missing=$((missing + 1))
            continue
        fi
        if [ -n "${sha512sums}" ]; then
            sum=$(openssl sha512 "${dstdir}/${filename}" | awk '{print $2}')
            rsum=$(grep ' '"$filename"\$ "${dstdir}/sha512sums.APKBUILD" | awk '{print $1}')
            if [ "${sum}" != "${rsum}" ]; then
                echo "Mismatched sh512 for $url into ${dstdir}/${filename}"
                if grep -qsi '^<!DOCTYPE html' "${dstdir}/${filename}"; then
                    >&2 echo "Bad DOCTYPE for $url into ${dstdir}/${filename}"
                    rm -f "${dstdir}/${filename}"
                elif grep -qsi 'Too many requests' "${dstdir}/${filename}"; then
                    >&2 echo "Too many requests for ${url}"
                    rm -f "${dstdir}/${filename}"
                elif grep -qsi '404 Not Found' "${dstdir}/${filename}"; then
                    >&2 echo "404 Not Found for ${url}"
                    rm -f "${dstdir}/${filename}"
                else
                    [ -n "$verbose" ] && echo "Bad content: $(cat "${dstdir}/${filename}")"
                fi
                # "Bad content" and "Too many requests" isn't really missing ...
                missing=$((missing + 1))
            else
                echo "$sum $filename" >> "${dstdir}/sha512sums.received"
            fi
        fi
    done
    if [ "$missing" != 0 ]; then
        echo "Missing/bad $missing files"
    fi
done

if [ -n "$urlfile" ]; then
    # shellcheck disable=SC2002
    [ -z "$quiet" ] && echo "Saved $(cat "$urlfile" |wc -l) URLs in $urlfile"
fi
cd "$startdir" || exit
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "Collected $(du -sm "$outdir" | cut -f 1) Mbytes for $(cat "${OCPAIRS}" | wc -l) packages of source in $outdir"
