ARG REL_HASH_LFEDGE_EVE_ALPINE

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS build

ENV PKGS mtools dosfstools
RUN eve-alpine-deploy.sh

COPY make-config /out/
RUN mkdir -p /out/conf/raw

FROM scratch
COPY --from=build /out /

WORKDIR /
ENTRYPOINT [ "/make-config" ]
