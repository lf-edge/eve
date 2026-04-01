# DON'T FORGET TO UPDATE THE HASH WHEN SOMETHING CHANGES!
# please see https://github.com/lf-edge/eve/blob/master/docs/BUILD.md#how-to-update-eve-alpine-package
FROM lfedge/eve-alpine-base:77cc1495c875b7468dbf4123210abf86a1ffb852-07a6e7df6 AS cache-build

ARG ALPINE_VERSION=3.22
# this is only needed once, when this package
# is rebased on the new version of Alpine and
# you have to have FROM alpine:x.y.z above:
# Trigger update for go package
RUN apk update && apk upgrade -a

# Copy Dockerfile so we can include it in the hash
COPY Dockerfile abuild.conf /etc/
COPY mirrors /tmp/mirrors/
COPY build-cache.sh /bin/

# install abuild for signing (which requires gcc as well)
# hadolint ignore=DL3018
RUN apk add --no-cache abuild gcc sudo

# install a new key into /etc/apk/keys
# hadolint ignore=DL3059
RUN abuild-keygen -a -i -n

# create all the mirrors
WORKDIR /tmp/mirrors

RUN [ -f /etc/apk/repositories.upstream ] || mv /etc/apk/repositories /etc/apk/repositories.upstream
# hadolint ignore=DL3059
RUN [ -f /etc/apk/cache.url ] || echo https://dl-cdn.alpinelinux.org/alpine > /etc/apk/cache.url
RUN for repo in main community testing; do \
    if [ ! -f "3.22/$repo" ]; then echo "skipping 3.22/$repo"; continue; fi &&\
    packages="" &&\
    if [ -f "3.22/$repo" ]; then packages="$packages $(cat "3.22/$repo")"; fi &&\
    if [ -f "3.22/$repo.$(apk --print-arch)" ]; then packages="$packages $(cat "3.22/$repo.$(apk --print-arch)")"; fi &&\
    if [ -n "$packages" ]; then build-cache.sh "3.22/$repo" "/mirror/$(dirname "3.22/$repo")" "$packages"; fi \
done

# set the default repository to use
RUN cp /mirror/${ALPINE_VERSION}/rootfs/etc/apk/repositories /etc/apk
RUN apk update

FROM lfedge/eve-alpine-base:77cc1495c875b7468dbf4123210abf86a1ffb852-07a6e7df6 AS compactor
ARG TARGETARCH
ARG GO_VERSION=1.24.6

COPY --from=cache-build /etc/apk/repositories* /etc/apk/
COPY --from=cache-build /etc/apk/keys /etc/apk/keys/
COPY --from=cache-build /mirror /mirror/
COPY eve-alpine-deploy.sh eve-cross-sysroot.sh go-compile.sh /bin/

RUN apk update && apk upgrade -a

ADD "https://go.dev/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz" /tmp/go.tar.gz
RUN rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz
RUN ln -s /usr/local/go/bin/go /usr/bin/go
RUN ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# define arch-specific envs
FROM scratch AS final-amd64
ENV EVE_BUILD_ARCH=x86_64
ENV EVE_TARGET_ARCH=x86_64
FROM scratch AS final-arm64
ENV EVE_BUILD_ARCH=aarch64
ENV EVE_TARGET_ARCH=aarch64
FROM scratch AS final-riscv64
ENV EVE_BUILD_ARCH=riscv64
ENV EVE_TARGET_ARCH=riscv64

# we merge layers in previous step
# so we should avoid large possible diff
# hadolint ignore=DL3006
FROM final-${TARGETARCH}
COPY --from=compactor / /
ENV GOTOOLCHAIN=local
CMD ["/bin/sh"]
