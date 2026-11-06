FROM lfedge/eve-alpine:cda433a7600c2486a9011c2de8b7e676483e25ac AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
