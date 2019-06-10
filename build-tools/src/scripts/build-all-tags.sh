#!/bin/bash

word_per_line() {
   for i in "$@" ; do echo "$i" ; done | sort -t. -n -k1,1 -k2,2 -k3,3
}

if [ $# -lt 2 ] ; then
   echo "Usage: $0 <docker hub repo to lookup tags in> <shell command to run for every missing one>"
   echo " e.g.: $0 lfedge/eve 'LINUXKIT_PKG_TARGET=push ; make pkgs ; make eve'"
   exit 1
fi

REPO=${1:-lfedge/eve}
CMD=${2:-"LINUXKIT_PKG_TARGET=push ; make pkgs ; make eve"}

case $(uname -m) in
  x86_64) ARCH=-amd64
    ;;
  aarch64) ARCH=-arm64
    ;;
  *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1
      ;;
esac

GIT_TAGS=$(git tag --sort=-creatordate | grep '[0-9]*\.[0-9]*\.[0-9]*')
# shellcheck disable=SC2086
LATEST_TAG=$(set $GIT_TAGS ; echo "$1")
DOCKER_TAGS=$(wget -q https://registry.hub.docker.com/v1/repositories/"$REPO"/tags -O -  | sed -e 's/[][]//g' -e 's/"//g' -e 's/ //g' | tr '}' '\n'  | cut -f3 -d: | grep '[0-9]*\.[0-9]*\.[0-9]*')
# shellcheck disable=SC2086
MISSING_TAGS=$(diff -u <(word_per_line $DOCKER_TAGS) <(word_per_line $GIT_TAGS | sed -e 's#$#'$ARCH'#') | sed -ne '/^+[^+]/s#^\+##p' | sed -e 's#'$ARCH'##')
MISSING_TAGS="$MISSING_TAGS origin/master"

echo "Building the following tags: $MISSING_TAGS (latest tag is ${LATEST_TAG})"

# Now build the tags
for t in $MISSING_TAGS ; do
   git clean -f -d -x
   git reset --hard "$t"

   eval "$CMD"
done
