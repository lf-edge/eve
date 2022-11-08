#!/bin/bash

set -e

yq() {
  docker run -i --rm  -v "${PWD}/":/workdir zededa/yq -y "$@"
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
                yq '(.services[] | select(.name == "pillar").image) |= "PILLAR_DEV_TAG"' "${out_templ_path}"
                ;;
        esac
    done
}

patch_version() {
    docker run -i --rm  -v "${PWD}/":/workdir zededa/yq -i -y --arg version "$1" '(.files[] | select(.contents == "EVE_VERSION")).contents |= $version' "$2"
}

main() {
    local base_templ_path="$1"
    local out_templ_path="$2"
    local eve_version="$3"

    if [ -e "${out_templ_path}".yq ]; then
        yq -f "${out_templ_path}".yq "${base_templ_path}"  >  "${out_templ_path}"  || exit 1
    else
        cp "${base_templ_path}" "${out_templ_path}"
    fi

    patch_version "${eve_version}" "${out_templ_path}"

    process-image-template "${out_templ_path}" "${eve_version}"
}

main "$@"
