#!/bin/sh
set -e

fakehash=$(echo "This is a fake" | sha256sum | awk '{print $1}')
generateOCITar() {
    local dir=./tmpbuilder
    local tarfile="$1"
    local config="$2"
    local confighash="$3"
    local layer="$4"
    local layerhash="$5"

    rm -rf $dir
    mkdir -p $dir
    # intentionally use fake data, so it will error out if not there
    configsize="5"
    if [ -n "$config" ]; then
        printf "%s" "$config" > $dir/config
        if [ -z "$confighash" ]; then
            confighash=$(cat $dir/config | sha256sum | awk '{print $1}')
        fi
        configsize=$(cat $dir/config | wc -c)
        mv $dir/config "${dir}/sha256:${confighash}"
    else
        confighash="${fakehash}"
    fi
    # intentionally use fake data, so it will error out if not there
    layersize="10"
    if [ -n "$layer" ]; then
        printf "%s" "$layer" > ${dir}/layer
        if [ -z "$layerhash" ]; then
            layerhash=$(cat ${dir}/layer | sha256sum | awk '{print $1}')
        fi
        layersize=$(cat ${dir}/layer | wc -c)
        mv ${dir}/layer "${dir}/${layerhash}.tar.gz"
    else
        layerhash="${fakehash}"
    fi
    export layerhash
    export confighash
    export layersize
    export configsize
    echo '{
   "schemaVersion": 2,
   "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
   "config": {
      "mediaType": "application/vnd.docker.container.image.v1+json",
      "size": ${configsize},
      "digest": "sha256:${confighash}"
   },
   "layers": [
      {
         "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
         "size": ${layersize},
         "digest": "sha256:${layerhash}"
      }
   ]
}
    ' | envsubst > ${dir}/manifest
    manifesthash=$(cat ${dir}/manifest | sha256sum | awk '{print $1}')
    mv ${dir}/manifest "${dir}/imagemanifest-${manifesthash}.json"
    tar -cvf "${tarfile}" -C "$dir" .
    printf "%s" "${manifesthash}" > "${tarfile}.hash"
    rm -rf "$dir"
}

#
# generate tar test files
# the tests in the parent directory assume the data as here

# clean out old ones
rm -f ./*.tar ./*.tar.hash

# case 1: just a basic tar file with basic txt to test reading it
# and calculating the hash
tar -cvf ./basic.tar ./basic.txt

# all other cases: actual OCI image tars
# - missing imagemanifest file - just use basic.tar
# - missing config file
# - mismatched config hash
# - missing layer file
# - mismatched layer hash
# - valid everything

# generateOCITar tarfile configcontents confighashoverride layercontents layerhashoverride
generateOCITar missingconfig.tar "" "" "layercontent" ""
generateOCITar mismatchedconfig.tar "configfoo" "${fakehash}" "layercontent" ""
generateOCITar missinglayer.tar "configfoo" "" "" ""
generateOCITar mismatchedlayer.tar "configfoo" "" "layercontent" "${fakehash}"
generateOCITar valid.tar "configfoo" "" "mylayer" ""
