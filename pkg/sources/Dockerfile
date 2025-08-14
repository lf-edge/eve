FROM lfedge/eve-alpine:cce89c6b13294f2ddaffe8ba7120833a2802a4d5 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
