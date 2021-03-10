FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools xorriso
RUN eve-alpine-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
