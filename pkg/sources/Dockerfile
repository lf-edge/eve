FROM lfedge/eve-alpine:3a8c6b2742af0f1e40d16063fb5ccfb1a1aece6f AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
