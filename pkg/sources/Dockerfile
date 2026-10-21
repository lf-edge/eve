FROM lfedge/eve-alpine:b4d0b9fe886ec5283e91da1ade3a47ed537bb47a AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
