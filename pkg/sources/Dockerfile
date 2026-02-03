FROM lfedge/eve-alpine:cfcc44432b107927b6a12da994750fe37ca3fc3b as tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
