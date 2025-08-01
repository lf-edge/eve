FROM lfedge/eve-alpine:2ed33236f1eea746532f612d6c4b7779c5da2193 as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
