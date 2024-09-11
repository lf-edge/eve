FROM lfedge/eve-alpine:82df60e43ab9f8c935584b8c7b4d0a4b0271d608 AS build

ENV PKGS dosfstools libarchive-tools binutils mtools xorriso
RUN eve-alpine-deploy.sh

RUN echo "mtools_skip_check=1" >> /out/etc/mtools.conf

FROM scratch
COPY --from=build /out /
COPY . /
WORKDIR /
ENTRYPOINT [ "/make-efi" ]
