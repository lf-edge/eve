FROM lfedge/eve-alpine:fb0a297e3939c06cd3e4a4b9293b4cf76847d9c0 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
