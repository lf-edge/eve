FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
