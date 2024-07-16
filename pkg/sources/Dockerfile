FROM lfedge/eve-alpine:e34284a8dd69c9c5ba7c52cd7b7d08fc2db1e0ac as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
