#!/bin/sh
set -e

##
#
# script to replace hashes in config files
# see usage() for usage and functionality
#

usage() {
    cat >&2 <<EOF
$0 --<mode> <how-to-find> <new-hash>

Available modes: --hash and --image

Replace by hash:
	$0 --hash <OLD> <NEW>
	Example: $0 --hash 8675309abcdefg abcdef567899
    	   Will replace all instances of 8675309abcdefg with abcdef567899

Replace by image: $0 --image <IMAGE> <NEW>
	$0 --image <IMAGE> <NEW>
	Example: $0 --image linuxkit/foo abcdef567899
	   Will tag all instances of linuxkit/foo with abcdef567899

        $0 --image <IMAGE>:<NEW> is accepted as a convenient shortcut for cutting
        and pasting e.g.the output of linuxkit pkg show-tag

EOF
}


# sufficient arguments
if [ $# -lt 3 ] ; then
    usage
    exit 1
fi

# which mode?
case "$1" in
    --hash)
	if [ $# -ne 3 ] ; then
	    usage
	    exit 1
	fi
        old=$2
        new=$3

        git grep -w -l "\b$old\b" | grep -v /vendor/ | xargs sed -i.bak -e "s,$old,$new,g"
        ;;
    --image)
	case $# in
	    2)
		image=${2%:*}
		hash=${2#*:}
		;;
	    3)
		image=$2
		hash=$3
		;;
	    esac
        git grep -E -l "[[:space:]]$image:" | grep -v /vendor/ | grep Dockerfile | xargs sed -i.bak -E -e "s,([[:space:]])($image):([^[:space:]]+), $image:$hash,g"
        ;;
    *)
        echo "Unknown mode $1"
        usage
        exit 1
        ;;
esac

find . -name '*.bak' | xargs rm
