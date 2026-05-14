FROM lfedge/eve-alpine:41f3648ded073c351d0dcd3432322f5816c9c7b1 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
