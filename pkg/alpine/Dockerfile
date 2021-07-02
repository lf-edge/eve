ARG EVE_BUILDER_IMAGE=alpine:3.14.0
FROM ${EVE_BUILDER_IMAGE} AS cache

ARG ALPINE_VERSION=3.14
# this is only needed once, when this package
# is rebased on the new version of Alpine and
# you have to have FROM alpine:x.y.z above:
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile abuild.conf /etc/
COPY mirrors /tmp/mirrors/
COPY build-cache.sh /bin/

# install abuild for signing (which requires gcc as well)
RUN apk add --no-cache abuild gcc sudo

# install a new key into /etc/apk/keys
RUN abuild-keygen -a -i -n

# create all the mirrors
WORKDIR /tmp/mirrors
RUN [ -f /etc/apk/repositories.upstream ] || mv /etc/apk/repositories /etc/apk/repositories.upstream
RUN [ -f /etc/apk/cache.url ] || echo https://dl-cdn.alpinelinux.org/alpine > /etc/apk/cache.url
RUN for p in */*; do build-cache.sh "$p" "/mirror/$(dirname "$p")" $(cat "$p") ; done

# set the default repository to use
RUN cp /mirror/${ALPINE_VERSION}/rootfs/etc/apk/repositories /etc/apk && apk update

FROM ${EVE_BUILDER_IMAGE}

COPY --from=cache /etc/apk/repositories* /etc/apk/
COPY --from=cache /etc/apk/keys /etc/apk/keys/
COPY --from=cache /mirror /mirror/
COPY eve-alpine-deploy.sh go-compile.sh /bin/

RUN apk update && apk upgrade -a
