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
# With -m <mirrorfile> use an alternate mirror configuration file; defaults to
# .mirrors.yaml next to this script. See that file for the format.

set -e

verbose=
tags=
evedir=
urlfile=
gitdir=
outdir=/tmp/$$
quiet=
prefix=
mirrorfile=$(cd "$(dirname "$0")" && pwd)/.mirrors.yaml
while getopts e:vt:u:s:g:qp:m: o
do      case "$o" in
        v)      verbose=1;;
        q)      quiet=1;;
        e)      evedir="$OPTARG";;
        t)      tags="$tags $OPTARG";;
        s)      outdir=$OPTARG;;
        u)      urlfile=$OPTARG;;
        g)      gitdir=$OPTARG;;
        p)      prefix=$OPTARG;;
        m)      mirrorfile=$OPTARG;;
        [?])    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-g <gitdir>] [-p <prefix>] [-m <mirrorfile>] [<version>]"
                exit 1;;
        esac
done
shift $((OPTIND-1))


if [ $# == 0 ] && [ -z "$tags" ] && [ -z "$evedir" ]; then
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-p <prefix>] [-m <mirrorfile>] [<version>]"
    exit 1
fi
if [ $# -gt 1 ]; then
    >&2 echo "Usage: $0 [-v] [-s <outdir>] [-u <urlfile>] [-t <tag>]+ [-e <evedir>] [-p <prefix>] [-m <mirrorfile>] [<version>]"
    exit 1
fi

checkdir=$outdir
[ -n "$prefix" ] && checkdir="$outdir/$prefix"

if [ -d "$checkdir" ]; then
    >&2 echo "$checkdir already exists"
    exit 1
fi

mkdir -p "$checkdir"

if [ -n "$gitdir" ] && [ ! -d "$gitdir" ]; then
    >&2 echo "gitdir $gitdir does not exist"
    exit 1
fi

startdir=$(pwd)
# ensure absolute path for outdir
outdir=$(readlink -f "${outdir}")
cd "$outdir" || exit 2
[ -n "$prefix" ] && mkdir -p "${outdir}/${prefix}"

[ -n "$verbose" ] && echo "outdir: $outdir" >&2
[ -n "$verbose" ] && echo "prefix: $prefix" >&2

# Collect all package origin and commit pairs in this file
OCPAIRS=/tmp/ocpairs.$$

# get_ocpairs <installed file> <ocpair output file>
get_ocpairs() {
    # Get pairs of origin and commit. Assumes commit is after origin
    # otherwise we produce XXX output string
    # Filter out duplicates
    awk -F: '
        /^P:/ { name=$2 }
        /^o:/ { origin=$2 }
        /^L:/ { license=$2 }
        /^V:/ { version=$2 }
        /^c:/ { commit=$2 }
        /^\s*$/ {
            if (origin != "") {
                if (commit ~ /^\s*$/) { commit="unknown" };
                print name, origin, version, commit, license;
                origin=""; license=""; version=""; name=""; commit="unknown";
            }
        }' | sort -u
}

# Mirrors. Several upstream servers referenced by the APKBUILD files drop or
# throttle requests coming from CI runners, so a source carrying a checksum is
# first looked up in the mirror table and only then fetched from its original
# location. Sources without a checksum are never taken from a mirror.
# Parallel indexed arrays are used instead of an associative array to keep
# working with the bash 3.x shipped by macOS.
MIRROR_PREFIXES=()
MIRROR_TARGETS=()

# yaml_scalar <value>: drop a trailing comment, trailing blanks and the
# surrounding quotes of a scalar.
yaml_scalar() {
    local v="$1"
    v="${v%%' #'*}"
    v="${v%"${v##*[![:space:]]}"}"
    case "$v" in
        \"*\")  v="${v#\"}"; v="${v%\"}";;
        \'*\')  v="${v#\'}"; v="${v%\'}";;
    esac
    printf '%s' "$v"
}

# load_mirrors <file>: read the mirror table. Only the restricted YAML subset
# documented in .mirrors.yaml is understood: a "mirrors:" mapping whose keys
# are URL prefixes and whose values are sequences of replacement prefixes.
load_mirrors() {
    local file="$1"
    local line trimmed idx=-1

    if [ ! -f "$file" ]; then
        [ -n "$verbose" ] && echo "no mirror configuration at $file" >&2
        return 0
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        trimmed="${line#"${line%%[![:space:]]*}"}"
        case "$trimmed" in
            ''|'#'*|'---'|'mirrors:') continue;;
        esac
        if [ "${trimmed#- }" != "$trimmed" ]; then
            if [ "$idx" -lt 0 ]; then
                >&2 echo "$file: mirror outside of any server entry: $line"
                continue
            fi
            MIRROR_TARGETS[idx]="${MIRROR_TARGETS[idx]}$(yaml_scalar "${trimmed#- }")"$'\n'
        elif [ "${trimmed%:}" != "$trimmed" ]; then
            idx=$((idx + 1))
            MIRROR_PREFIXES[idx]=$(yaml_scalar "${trimmed%:}")
            MIRROR_TARGETS[idx]=""
        else
            >&2 echo "$file: ignoring unsupported line: $line"
        fi
    done < "$file"
    [ -n "$verbose" ] && echo "loaded mirrors for ${#MIRROR_PREFIXES[@]} servers from $file" >&2
    return 0
}

# mirror_candidates <url>: print the locations to try for a URL, one per line,
# mirrors of the first matching prefix first and the original URL last.
mirror_candidates() {
    local url="$1"
    local i=0 prefix rest m

    while [ "$i" -lt "${#MIRROR_PREFIXES[@]}" ]; do
        prefix="${MIRROR_PREFIXES[$i]}"
        case "$url" in
            "$prefix"*)
                rest="${url#"$prefix"}"
                while IFS= read -r m; do
                    [ -n "$m" ] && printf '%s\n' "${m%/}/${rest#/}"
                done <<< "${MIRROR_TARGETS[$i]}"
                break
                ;;
        esac
        i=$((i + 1))
    done
    printf '%s\n' "$url"
}

# An HTTP error carrying a body ("404 Not Found", "Too many requests", ...) is
# what bad_content_tag() classifies, and --fail throws that body away. Keep it
# with --fail-with-body where curl is recent enough (>= 7.76), and settle for
# the coarser "missing" tag on older ones.
CURL_FAILOPT=--fail
if curl --help all 2>/dev/null | grep -q -- '--fail-with-body'; then
    CURL_FAILOPT=--fail-with-body
fi

# bad_content_tag <file>: classify a file we did not want: an error page served
# with a 200, the body of an HTTP error, or a tarball failing its checksum. The
# named pages are looked for before the generic markup check, being HTML too.
bad_content_tag() {
    local f="$1"
    if grep -qsi 'Too many requests' "$f"; then
        echo "too-many-requests"
    elif grep -qsi '404 Not Found' "$f"; then
        echo "404-not-found"
    elif grep -qsi '^<!DOCTYPE html' "$f"; then
        echo "bad-content"
    else
        echo "mismatched-sh512"
    fi
}

# download_source <url> <destination> <verify 0|1> <expected sha512>
# Walk the mirrors of the URL until one hands out a file matching the checksum
# from the APKBUILD, and keep nothing that did not match. The sha512 of the
# file actually received is printed on success; on failure a tag describing the
# error is printed instead, content errors taking precedence over plain
# unreachability.
download_source() {
    local url="$1" dst="$2" verify="$3" expected="$4"
    local candidates candidate sum newtag tag=
    local -a curlopts

    if [ "$verify" = 1 ]; then
        candidates=$(mirror_candidates "$url")
    else
        # Without a checksum in the APKBUILD nothing tells the real file apart
        # from an error page served with a 200, so a source that cannot be
        # verified is only ever fetched from the server Alpine points at.
        candidates="$url"
    fi
    if [ "$candidates" = "$url" ]; then
        # single chance, be patient
        curlopts=(--connect-timeout 30 --retry 3 --retry-delay 5 --max-time 1800)
    else
        # the mirror list is the fallback, so give up on each candidate quickly
        # instead of waiting on a server that is dropping our requests
        curlopts=(--connect-timeout 10 --retry 1 --retry-delay 3
                  --speed-limit 1024 --speed-time 30 --max-time 600)
    fi
    while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        [ "$candidate" != "$url" ] && echo "Trying mirror $candidate for $url" >&2
        if ! curl -sSL "$CURL_FAILOPT" "${curlopts[@]}" -o "$dst" "$candidate"; then
            >&2 echo "Failed to download $candidate"
            newtag=missing
            if [ -s "$dst" ]; then
                # the error page says more than the transfer having failed,
                # unless it matches nothing we know how to name
                newtag=$(bad_content_tag "$dst")
                [ "$newtag" = "mismatched-sh512" ] && newtag=missing
            fi
            # a content error already seen outranks plain unreachability
            { [ -z "$tag" ] || [ "$tag" = missing ]; } && tag="$newtag"
            rm -f "$dst"
            continue
        fi
        [ "$verify" != 1 ] && return 0
        sum=$(openssl sha512 "$dst" | awk '{print $2}')
        if [ "$sum" = "$expected" ]; then
            printf '%s' "$sum"
            return 0
        fi
        tag=$(bad_content_tag "$dst")
        >&2 echo "Mismatched sh512 ($tag) for $candidate into $dst"
        rm -f "$dst"
    done <<< "$candidates"
    echo "${tag:-missing}"
    return 1
}

load_mirrors "$mirrorfile"

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
        [ -n "$verbose" ] && echo "retrieving installed databases for $TAG" >&2
        docker run --rm --entrypoint=sh "${TAG}" -c "unsquashfs -d /newroot /bits/rootfs.img >/dev/null && find /newroot -wholename '*lib/apk/db/installed' -exec cat {} \;" | get_ocpairs >> "${tmppairs}"
        echo >> ${tmppairs}
    done
    cat ${tmppairs} | sort -u > ${OCPAIRS}
fi


# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages times licenses" >&2
# skip licenses
mv ${OCPAIRS} ${OCPAIRS}.with_licenses
awk '{print $1, $2, $3, $4}' ${OCPAIRS}.with_licenses | sort -u >${OCPAIRS}
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "found $(cat ${OCPAIRS} |wc -l) packages" >&2

badfilescount=0
badfileslist=""

TMP_DIR=$(mktemp -d)
if [ -n "$gitdir" ]; then
    cp -r "$gitdir/." "${TMP_DIR}"
else
    pkgurl="https://git.alpinelinux.org/aports.git"
    cloned=
    while IFS= read -r candidate; do
        [ -z "$candidate" ] && continue
        [ "$candidate" != "$pkgurl" ] && echo "Trying mirror ${candidate} for ${pkgurl}" >&2
        rm -rf "${TMP_DIR}"
        if git clone "${candidate}" "${TMP_DIR}" >/dev/null; then
            cloned=1
            break
        fi
        >&2 echo "Failed to clone ${candidate}"
    done <<< "$(mirror_candidates "${pkgurl}")"
    if [ -z "$cloned" ]; then
        >&2 echo "Failed to clone ${pkgurl}"
        exit 2
    fi
fi

# shellcheck disable=SC2002
while read -r line ; do
    # shellcheck disable=SC2086
    set -- $line
    [ $# -lt 4 ] && continue
    name=$1
    origin=$2
    version=$3
    commit=$4
    shift 4
    license="$*"
    # The commit is empty in one case... That is from the eve-debug container
    # Could ignore
    if [ "${commit}" = "unknown" ]; then
        echo "Ignoring ${origin} with empty commit; from eve-debug package" >&2
        continue
    fi
    commitstr="?id=${commit}"

    # Include commit in directory to handle different versions of the same package.
    # The actual download is based on the origin, but we indicate all names. There might
    # be several for the same origin (and therefore same source).
    name_version="${name}-${version}"
    origin_version="${origin}-${version}"
    pkgbasepath="${origin_version}.${commit}"
    pkgpath="${pkgbasepath}"
    [ -n "$prefix" ] && pkgpath="${prefix}/${pkgpath}"
    dstdir="${outdir}/${pkgpath}"
    [ -n "$verbose" ] && echo "origin: ${origin} commit: ${commit} dstdir: ${dstdir}" >&2
    # we might already have this package, in which case, all we need is the line to output
    if [ -d "${dstdir}" ]; then
        echo "Already have ${origin} at ${commit}" >&2
    else
        # Need to handle main, community and testing repos
        foundRepo=""
        git -C "${TMP_DIR}" checkout "${commit}" >/dev/null
        for repo in main community testing; do
                echo "Trying ${origin} in ${repo} at commit ${commit}" >&2
                sourceDir="${TMP_DIR}/${repo}/${origin}"
                if [ ! -d "${sourceDir}" ]; then
                    echo "${origin} not in ${repo} at commit ${commit}" >&2
                    continue
                fi
                if [ ! -f "${sourceDir}"/APKBUILD ]; then
                    echo "${origin} in ${repo} missing APKBUILD" >&2
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
        [ -n "$verbose" ] && echo "Retrieved ${origin} ${commit}" >&2
        if [ -n "$urlfile" ]; then
            pkgurl="https://git.alpinelinux.org/aports/plain/${foundRepo}/${origin}/APKBUILD${commitstr}"
            echo "$origin $pkgurl $license" >>"${urlfile}" >&2
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
            verify=0
            rsum=
            recvsum=
            if [ -n "${sha512sums}" ]; then
                rsum=$(grep ' '"$filename"\$ "${dstdir}/sha512sums.APKBUILD" | awk '{print $1}')
                if [ -n "${rsum}" ]; then
                    verify=1
                else
                    # nothing to verify against, so no mirror and no rejecting
                    # a file the origin server may well have served correctly
                    >&2 echo "No sha512sum for ${filename} in ${pkgpath}"
                fi
            fi
            case $url in
                https://*|http://*|ftp://*)
                    [ -n "$verbose" ] && echo "found $s basename ${filename}" >&2
                    # mirrors and checksum verification are handled together so
                    # that a mirror serving bad content falls through to the next
                    if ! outmsg=$(download_source "${url}" "${dstdir}/${filename}" "${verify}" "${rsum}"); then
                        >&2 echo "Failed to retrieve $url"
                        # "Bad content" and "Too many requests" isn't really missing ...
                        badfileslist="${badfileslist} ${outmsg}:${pkgpath}:${filename}"
                        badfilescount=$((badfilescount + 1))
                        continue
                    fi
                    recvsum="${outmsg}"
                    ;;
                *)
                    [ -n "$verbose" ] && echo "not http*: $s" >&2
                    if [ ! -f "${dstdir}/${filename}" ]; then
                        >&2 echo "Missing file ${filename} $url"
                        badfileslist="${badfileslist} missing:${pkgpath}:${filename}"
                        badfilescount=$((badfilescount + 1))
                        continue
                    fi
                    if [ "${verify}" = 1 ]; then
                        sum=$(openssl sha512 "${dstdir}/${filename}" | awk '{print $2}')
                        recvsum="${sum}"
                        if [ "${sum}" != "${rsum}" ]; then
                            errmsg=$(bad_content_tag "${dstdir}/${filename}")
                            echo "Mismatched sh512 for $url into ${dstdir}/${filename}" >&2
                            badfileslist="${badfileslist} ${errmsg}:${pkgpath}:${filename}"
                            badfilescount=$((badfilescount + 1))
                            continue
                        fi
                    fi
                    ;;
            esac
            if [ "${verify}" = 1 ]; then
                echo "$recvsum $filename" >> "${dstdir}/sha512sums.received"
            fi
        done
        if [ "$badfilescount" != 0 ]; then
            echo "Missing/bad $badfilescount files" >&2
        fi
    fi

    echo "alpine,$name_version,$commit,$pkgpath"
done < "${OCPAIRS}"

# clean up our temporary cloned directory
rm -rf "$TMP_DIR"
sync

if [ -n "$urlfile" ]; then
    # shellcheck disable=SC2002
    [ -z "$quiet" ] && echo "Saved $(cat "$urlfile" |wc -l) URLs in $urlfile" >&2
fi
cd "$startdir" || exit
# shellcheck disable=SC2002
[ -z "$quiet" ] && echo "Collected $(du -sm "$outdir" | cut -f 1) Mbytes for $(cat "${OCPAIRS}" | wc -l) packages of source in $outdir" >&2

# any errors?
if [ -n "$badfileslist" ]; then
    echo "Missing/bad $badfilescount files" >&2
    for b in $badfileslist; do
        echo "  $b" >&2
    done
fi

# report every package we output
