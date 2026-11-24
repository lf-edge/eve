FROM lfedge/eve-alpine:1f42cfeeb539f80de28baada31772dbf8f18b3fe AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
