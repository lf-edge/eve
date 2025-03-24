# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:0f2e0da38e30753c68410727a6cc269e57ff74f2 as build
ENV BUILD_PKGS linux-headers musl-dev musl-utils musl-libintl git gcc g++ \
               autoconf automake libtool make flex bison bash sed gettext
ENV PKGS alpine-baselayout
RUN eve-alpine-deploy.sh

ADD https://gitlab.com/apparmor/apparmor.git#v3.1.4 /apparmor
WORKDIR /apparmor/libraries/libapparmor
RUN ./autogen.sh && \
    ./configure && \
    make

WORKDIR /apparmor/parser
RUN ../common/list_af_names.sh > base_af_names.h && \
    make

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=build /out/ /
COPY --from=build /apparmor/parser/apparmor_parser /usr/bin/
COPY /etc/ /etc
COPY /profiles/* /etc/apparmor.d
COPY aa-init.sh /

WORKDIR /
ENTRYPOINT []
CMD ["/aa-init.sh"]
