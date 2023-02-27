FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb AS build

ENV PKGS mtools dosfstools
RUN eve-alpine-deploy.sh

COPY make-config /out/
RUN mkdir -p /out/conf/raw

FROM scratch
COPY --from=build /out /

WORKDIR /
ENTRYPOINT [ "/make-config" ]
