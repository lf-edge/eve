FROM lfedge/eve-alpine:a6a101a68aa7269506dbcb8a0a45c0d69e4f851b AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
