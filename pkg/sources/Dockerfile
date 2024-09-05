FROM lfedge/eve-alpine:82df60e43ab9f8c935584b8c7b4d0a4b0271d608 as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
