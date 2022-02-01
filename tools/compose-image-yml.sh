#!/bin/bash

main() {
    local base_templ_path="$1"
    local out_templ_path="$2"
    local eve_version="$3"

    local out_dir
    local tock_str

    out_dir="$(dirname "${out_templ_path}")"
    tock_str="$(basename "${out_templ_path}")"
    tock_str=${tock_str%.yml.in.new}
    IFS="-" read -r -a tockens <<< "${tock_str}"

    echo "out_templ_path is ${out_templ_path}"

    cp "${base_templ_path}" "${base_templ_path}".sed
    for i in "${tockens[@]}"; do
        local patch_name="${out_dir}"/"$i".patch
        echo "checking ${patch_name}"
        if [ -e "${patch_name}" ]; then
            patch -p0 -i "${patch_name}"
        fi
    done

    sed "s/EVE_VERSION/${eve_version}/g" <  "${base_templ_path}".sed > "${out_templ_path}"
}

main "$@"
