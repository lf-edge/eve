FROM lfedge/eve-alpine:99db0c3af59a9656315c9d7a0ad8a24f631134b0 as build
ENV PKGS wireless-tools wpa_supplicant
RUN eve-alpine-deploy.sh

COPY init.sh /init.sh

FROM scratch
COPY --from=build /out/ /

ENTRYPOINT []
CMD ["/init.sh"]
