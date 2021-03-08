ARG ALPINE_VERSION=3.13
# FROM lfedge/eve-alpine:5.16.0 AS cache

FROM alpine:${ALPINE_VERSION} AS mirror
ARG ALPINE_VERSION=3.13

# pull packages from a *previous* mirror
# COPY --from=cache /mirror /mirror

# update base image
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile /etc/
COPY mirrors /tmp/mirrors/
COPY build-cache.sh /bin/

# install abuild for signing (which requires gcc as well)
RUN apk add --no-cache abuild gcc

# install a new key into /etc/apk/keys
RUN abuild-keygen -a -i -n

# create all the mirrors
WORKDIR /tmp/mirrors
RUN mv /etc/apk/repositories /etc/apk/repositories.upstream
RUN for p in */*; do build-cache.sh "$p" "/mirror/$(dirname "$p")" $(cat "$p") ; done

# set the default repository to use
RUN cp /mirror/${ALPINE_VERSION}/rootfs/etc/apk/repositories /etc/apk && apk update

FROM alpine:${ALPINE_VERSION}

COPY --from=mirror /etc/apk/repositories* /etc/apk/
COPY --from=mirror /etc/apk/keys /etc/apk/keys/
COPY --from=mirror /mirror /mirror/
COPY eve-alpine-deploy.sh go-compile.sh /bin/

RUN apk update && apk upgrade -a
