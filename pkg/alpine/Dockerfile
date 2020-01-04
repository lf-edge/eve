FROM alpine:3.9 AS mirror

# update base image
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile /Dockerfile
COPY packages* /tmp/

# mirror packages
RUN cat /tmp/packages.$(uname -m) >> /tmp/packages && \
   mkdir -p /mirror/$(apk --print-arch) && \
   apk fetch --recursive -o /mirror/$(apk --print-arch) $(apk info; cat /tmp/packages)

# install abuild for signing
RUN apk add --no-cache abuild

# install a new key into /etc/apk/keys
RUN abuild-keygen -a -i -n

# index the new repo
RUN apk index --rewrite-arch $(apk --print-arch) -o /mirror/$(apk --print-arch)/APKINDEX.unsigned.tar.gz /mirror/$(apk --print-arch)/*.apk

# sign the index
RUN cp /mirror/$(apk --print-arch)/APKINDEX.unsigned.tar.gz /mirror/$(apk --print-arch)/APKINDEX.tar.gz
RUN abuild-sign /mirror/$(apk --print-arch)/APKINDEX.tar.gz

# set this as our repo but keep a copy of the upstream for downstream use
RUN mv /etc/apk/repositories /etc/apk/repositories.upstream && echo "/mirror" > /etc/apk/repositories && apk update

FROM alpine:3.9

COPY --from=mirror /etc/apk/repositories /etc/apk/repositories
COPY --from=mirror /etc/apk/repositories.upstream /etc/apk/repositories.upstream
COPY --from=mirror /etc/apk/keys /etc/apk/keys/
COPY --from=mirror /mirror /mirror/
COPY --from=mirror /Dockerfile /Dockerfile

RUN apk update && apk upgrade -a
