#!/bin/bash

set -e

yq() {
  docker run -i --rm -v "${PWD}/":/workdir -w /workdir mikefarah/yq:4.40.5 "$@"
}

process-image-template() {
    local out_templ_path="$1"
    local eve_version="$2"

    local flags
    local -a bits

    # Drop everything before the git hashcode (including the hash)
    flags="$(sed -r 's/.*[0-9a-fA-F]{8}(.*)/\1/p' <<< "${eve_version}")"
    # Drop dirty flag
    flags="$(sed -r 's/-dirty[0-9.\-]{18}//g' <<< "${flags}")"
    IFS='-' read -r -a bits <<< "${flags}"

    for bit in "${bits[@]}"; do
        case "${bit}" in
            dev)
                # shellcheck disable=SC2094
                yq '(.onboot[] | select(.image == "PILLAR_TAG").image) |= "PILLAR_DEV_TAG"' < "${out_templ_path}" | spongefile "${out_templ_path}"
                # shellcheck disable=SC2094
                yq '(.services[] | select(.image == "PILLAR_TAG").image) |= "PILLAR_DEV_TAG"' < "${out_templ_path}" | spongefile "${out_templ_path}"
                ;;
        esac
    done
}

patch_hv() {
    # note that we have to do that careful shell substitution, because yq 4
    # doesn't support passing in a variable as the value to --arg, requiring
    # setting it as an env var; which is more difficult to do when passed to docker
    # shellcheck disable=SC2016,SC2094
    yq '(.files[] | select(.contents == "EVE_HV")).contents |= "'"$1"'"' < "$2" | spongefile "$2"
}

# because sponge doesn't exist everywhere, and this one uses a tmpfile
spongefile() {
    local tmp=""
    tmp=$(mktemp)
    cat > "$tmp"
    cat "$tmp" > "$1"
    rm "$tmp"
}

main() {
    local base_templ_path=""
    local out_templ_path=""
    local eve_version=""
    local eve_hv=""

    while getopts "b:o:v:h:" opt; do
        case ${opt} in
            b )
                base_templ_path=$OPTARG
                ;;
            o )
                out_templ_path=$OPTARG
                ;;
            v )
                eve_version=$OPTARG
                ;;
            h )
                eve_hv=$OPTARG
                ;;
            \? )
                echo "Invalid option: -$OPTARG" 1>&2
                exit 1
                ;;
            : )
                echo "Invalid option: -$OPTARG requires an argument" 1>&2
                exit 1
                ;;
        esac
    done
    shift $((OPTIND -1))
    if [ -z "$out_templ_path" ] || [ -z "$eve_version" ] || [ -z "$eve_hv" ] || [ -z "$base_templ_path" ]; then
        usage
    fi
    local modifiers="$*"

    cp "${base_templ_path}" "${out_templ_path}"

    for modifier in ${modifiers}; do
        if [ ! -f "${modifier}" ]; then
            continue
        fi
        # shellcheck disable=SC2094
        yq --from-file "${modifier}" < "${out_templ_path}" | spongefile "${out_templ_path}"|| exit 1
    done

    patch_hv "${eve_hv}" "${out_templ_path}"

    process-image-template "${out_templ_path}" "${eve_version}"
}

usage() {
    echo "Usage: $0 -b <base template> -o <output template> -v <eve version> -h <eve hv> <modifiers>"
    exit 1
}

main "$@"
