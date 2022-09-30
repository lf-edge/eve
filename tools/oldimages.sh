#!/bin/sh

# get all of the lfedge images
IMGS=$(docker image ls --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}"  --filter reference='lfedge/*')
# get the image names without tags
IMGNAMES=

# limit to just a few as an option
if [ $# -gt 0 ]; then
    IMGNAMES="$@"
else
    IMGNAMES=$(echo "$IMGS" | awk '{print $1}' | sort | uniq)
fi

# find the IDs of each image name, all but the most recent
IMGIDS=""
for i in $IMGNAMES; do
    TMPIDS=$(echo "$IMGS" | grep -w "^$i" | awk '{print $3}' | uniq)
    IDCOUNT=$(echo "$TMPIDS" | wc -w)
    if [ $IDCOUNT -gt 1 ]; then
        TMPIDS=$(echo "$TMPIDS" | tail -n +2)
        IMGIDS="$IMGIDS $TMPIDS"
    fi
done

echo $IMGIDS
