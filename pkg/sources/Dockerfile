FROM lfedge/eve-alpine:e9cb3b035e264f89523f8eca848e8baa68a1fbfd AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
