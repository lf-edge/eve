FROM lfedge/eve-alpine:d1cee9f3e9b1a2f336a61ec1178121a968b4710d AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
