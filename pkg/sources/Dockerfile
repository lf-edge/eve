FROM lfedge/eve-alpine:080e2b4c683508649d72d2ae9b166153d819ca5d AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
