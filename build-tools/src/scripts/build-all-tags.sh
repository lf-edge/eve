#!/bin/bash

word_per_line() {
   for i in $* ; do echo $i ; done | sort -t. -n -k1,1 -k2,2 -k3,3
}

run() {
   $DRY_RUN "$@"
}

REPO="$1"

case $(uname -m) in
  x86_64) ARCH=-amd64
    ;;
  aarch64) ARCH=-arm64
    ;;
  *) echo "Unsupported architecture $(uname -m). Exiting" && exit 1
      ;;
esac

GIT_TAGS=$(cd $REPO ; git tag --sort=-creatordate | grep '[0-9]*\.[0-9]*\.[0-9]*')
LATEST_TAG=$(set $GIT_TAGS ; echo $1)
DOCKER_TAGS=$(wget -q https://registry.hub.docker.com/v1/repositories/zededa/$REPO/tags -O -  | sed -e 's/[][]//g' -e 's/"//g' -e 's/ //g' | tr '}' '\n'  | cut -f3 -d: | grep '[0-9]*\.[0-9]*\.[0-9]*')
DOCKER_TAGS=${DOCKER_TAGS:-$(wget -q https://registry.hub.docker.com/v1/repositories/zededa/zenix/tags -O -  | sed -e 's/[][]//g' -e 's/"//g' -e 's/ //g' | tr '}' '\n'  | cut -f3 -d: | grep '[0-9]*\.[0-9]*\.[0-9]*')}
diff -u <(word_per_line $DOCKER_TAGS) <(word_per_line $GIT_TAGS | sed -e 's#$#'$ARCH'#')
MISSING_TAGS=$(diff -u <(word_per_line $DOCKER_TAGS) <(word_per_line $GIT_TAGS | sed -e 's#$#'$ARCH'#') | sed -ne '/^+[^+]/s#^\+##p' | sed -e 's#'$ARCH'##')
# MISSING_TAGS=${MISSING_TAGS:-origin/master}
MISSING_TAGS="$MISSING_TAGS origin/master"

echo "Building the following tags: $MISSING_TAGS (latest tag is ${LATEST_TAG})"

# Now build the tags
cd $REPO

for t in $MISSING_TAGS ; do
   case $t in
     "$LATEST_TAG") HUMAN_TAG=latest ; TAG=$t ;;
     origin/master) HUMAN_TAG=snapshot ; TAG=  ;;
                 *) HUMAN_TAG= ; TAG=$t ;;
   esac

   run git clean -f -d -x
   run git reset --hard $t

  LK_HASH_REL="${TAG:+--hash} $TAG ${HUMAN_TAG:+--release} $HUMAN_TAG"

   if [ "$REPO" = zcli -a "$HUMAN_TAG" = snapshot ] ; then
      run linuxkit pkg push --disable-content-trust $LK_HASH_REL -build-yml build-dev.yml .
      run make docker-build docker-push
   elif [ $REPO = zenbuild ] ; then
      run make ${TAG:+ZENIX_HASH=}$TAG ${HUMAN_TAG:+ZENIX_REL=}$HUMAN_TAG DEFAULT_PKG_TARGET=push pkgs zenix
   else
      run linuxkit pkg push --disable-content-trust $LK_HASH_REL .
   fi
done
