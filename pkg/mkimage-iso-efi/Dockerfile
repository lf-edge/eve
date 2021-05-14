ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.2.0
FROM ${EVE_BUILDER_IMAGE} AS build

ENV PKGS dosfstools libarchive-tools binutils mtools xorriso
RUN eve-alpine-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
