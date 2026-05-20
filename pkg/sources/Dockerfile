FROM lfedge/eve-alpine:325b12087b386811fdb9d3c0adffa5fb94a34b95 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
