FROM lfedge/eve-alpine:4635a9f93267ec0e24005aa80f2e7b1b828e5d17 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
