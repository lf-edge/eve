FROM lfedge/eve-alpine:a5f43dc9196cd02f5aeba42b9ddaeb4ff76f565c AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
