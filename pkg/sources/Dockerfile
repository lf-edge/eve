FROM lfedge/eve-alpine:b1b51db20be9651c521bf5ba14eb5c6d7481eed7 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
