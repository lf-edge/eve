FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
