# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-ubuntu:17fea35e37517165b27e0e3f142d38750eb0a544 AS build
ENV BUILD_PKGS="linux-libc-dev libc6-dev git gcc g++ \
               autoconf autoconf-archive automake libtool make flex bison \
               bash sed gettext pkg-config"
ENV PKGS="libstdc++6"
RUN eve-ubuntu-deploy.sh

ADD https://gitlab.com/apparmor/apparmor.git#v4.1.3 /apparmor
WORKDIR /apparmor/libraries/libapparmor
RUN ./autogen.sh
RUN ./configure
RUN make -j "$(getconf _NPROCESSORS_ONLN)"

WORKDIR /apparmor/parser
RUN ../common/list_af_names.sh > base_af_names.h
RUN make CFLAGS="-Os"

# Register apparmor in the dpkg status area, mandatory for it to be included in the SBOM.
RUN register-sbom-pkg.sh -n apparmor -v 4.1.3 -l GPL-2.0-only -u https://gitlab.com/apparmor/apparmor.git

#Pull a selected set of artifacts into the final stage.
FROM scratch
COPY --from=build /out/ /
COPY --from=build /apparmor/parser/apparmor_parser /usr/bin/
COPY /etc/ /etc
COPY /profiles/* /etc/apparmor.d
COPY aa-init.sh /

RUN for i in /etc/apparmor.d/*.*; do echo "-- $i --"; /usr/bin/apparmor_parser -Q "$i"; done

WORKDIR /
ENTRYPOINT []
CMD ["/aa-init.sh"]
