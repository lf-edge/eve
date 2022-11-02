#!/bin/sh

CACHE="/mirror/$1/$(apk --print-arch)"
APORTS="/aports"

packages=""
if [ -f "$APORTS/eve" ]; then packages="$packages $(cat "$APORTS/eve")"; fi
if [ -f "$APORTS/eve.$(apk --print-arch)" ]; then packages="$packages $(cat "$APORTS/eve.$(apk --print-arch)")"; fi

for p in ${packages}; do
  su builder -c "cd $APORTS/$p && abuild checksum && abuild -r"
done

cp /home/builder/packages/aports/$(apk --print-arch)/*.apk "$CACHE/"

# index the cache
rm -f "$CACHE"/APKINDEX*
apk index --rewrite-arch "$(apk --print-arch)" -o "$CACHE/APKINDEX.unsigned.tar.gz" "$CACHE"/*.apk
cp "$CACHE/APKINDEX.unsigned.tar.gz" "$CACHE/APKINDEX.tar.gz"
abuild-sign "$CACHE/APKINDEX.tar.gz"
