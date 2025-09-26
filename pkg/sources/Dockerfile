ARG REL_HASH_LFEDGE_EVE_ALPINE

FROM ${REL_HASH_LFEDGE_EVE_ALPINE} AS tools

COPY collected_sources.tar.gz /var/collected_sources.tar.gz
RUN mkdir -p /var/sources && tar -C /var/sources -xzf /var/collected_sources.tar.gz

FROM scratch
COPY --from=tools /var/sources /
