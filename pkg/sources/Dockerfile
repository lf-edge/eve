FROM lfedge/eve-alpine:1fdf3241f1aef1dd3e8ad7433c85474bc522f3f5 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
