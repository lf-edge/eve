ARG EVE_BUILDER_IMAGE=lfedge/eve-alpine:6.7.0
FROM ${EVE_BUILDER_IMAGE} AS build

ENV PKGS mtools dosfstools
RUN eve-alpine-deploy.sh

COPY make-config /out/
RUN mkdir -p /out/conf/raw

FROM scratch
COPY --from=build /out /

WORKDIR /
ENTRYPOINT [ "/make-config" ]
