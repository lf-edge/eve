FROM lfedge/eve-alpine:1f744180283ffb4eabcc3862531aeacf1de886b3 AS build

ENV PKGS mtools dosfstools
RUN eve-alpine-deploy.sh

COPY make-config /out/
RUN mkdir -p /out/conf/raw

FROM scratch
COPY --from=build /out /

WORKDIR /
ENTRYPOINT [ "/make-config" ]
