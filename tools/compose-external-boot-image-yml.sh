#!/bin/bash

set -e

yq() {
  docker run -i --rm -v "${PWD}/":/workdir intoiter/yq:3.1.0 -y -i "$@"
}

patch_xentools() {
    yq ".buildArgs[1] |= \"XENTOOLS=$1\"" "$2"
}

patch_kernel() {
    yq ".buildArgs[0] |= \"KERNEL=$1\"" "$2"
}
main() {
    local base_templ_path="$1"
    local out_templ_path="$2"
    local kernel_tag="$3"
    local xentools_tag="$4"

    cp "${base_templ_path}" "${out_templ_path}"

    # Replace kernel_tag
    patch_kernel "${kernel_tag}" "${out_templ_path}"
    # Replace xentools_tag
    patch_xentools "${xentools_tag}" "${out_templ_path}"
}

main "$@"
