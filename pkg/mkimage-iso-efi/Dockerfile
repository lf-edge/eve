FROM lfedge/eve-alpine:145f062a40639b6c65efa36bed1c5614b873be52 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools xorriso
RUN eve-alpine-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
