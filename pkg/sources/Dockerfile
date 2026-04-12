FROM lfedge/eve-alpine:a2d89e72b4c3ea2ddd4b807209bf9bdad19669fe AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
