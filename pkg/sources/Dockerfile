FROM lfedge/eve-alpine:61283a3a978a7cdc9073a1ba678717fc3ea1fe97 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
