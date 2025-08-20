FROM lfedge/eve-alpine:745ae9066273c73b0fd879c4ba4ff626a8392d04 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
