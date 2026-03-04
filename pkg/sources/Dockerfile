FROM lfedge/eve-alpine:000e3b2bc3c441f8a0bb7f60921c394b60544c56 AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
