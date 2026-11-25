FROM lfedge/eve-alpine:2e8bb7ac88e47c8dd32369167d2fab3528e282a3 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
