FROM lfedge/eve-alpine:f9b45a5a3b3a18a8503cbe6d1258a1025450fe0e AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
