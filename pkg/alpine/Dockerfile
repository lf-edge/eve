ARG ALPINE_VERSION=3.9
FROM lfedge/eve-alpine:a653b9e953fabc6bd2ec07899a050e625786f76b AS cache

FROM alpine:${ALPINE_VERSION} AS mirror
ARG ALPINE_VERSION=3.9

# pull packages from a *previous* mirror
COPY --from=cache /mirror /mirror

# update base image
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile /Dockerfile
COPY mirrors /tmp/mirrors/
COPY build-cache.sh /bin/

# install abuild for signing (which requires gcc as well)
RUN apk add --no-cache abuild gcc

# install a new key into /etc/apk/keys
RUN abuild-keygen -a -i -n

# create all the mirrors
RUN for p in /tmp/mirrors/[0-9]*; do v="$(basename "$p")" ;\
      build-cache.sh "$v" "/mirror/$v" $(cat "$p")        ;\
      echo "/mirror/$v" > "/etc/apk/repositories.$v"      ;\
    done
    
# set the default repository to use
RUN mv /etc/apk/repositories /etc/apk/repositories.upstream && cp /etc/apk/repositories.${ALPINE_VERSION} /etc/apk/repositories && apk update

FROM alpine:${ALPINE_VERSION}

COPY --from=mirror /etc/apk/repositories* /etc/apk/
COPY --from=mirror /etc/apk/keys /etc/apk/keys/
COPY --from=mirror /mirror /mirror/
COPY --from=mirror /Dockerfile /Dockerfile

RUN apk update && apk upgrade -a
