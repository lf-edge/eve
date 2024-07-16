# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:e34284a8dd69c9c5ba7c52cd7b7d08fc2db1e0ac as build
ENV BUILD_PKGS go
ENV PKGS alpine-baselayout dbus glib udev libgudev libmbim libmbim-tools libqmi libqrtr-glib libmm-glib qmi-utils picocom modemmanager
RUN eve-alpine-deploy.sh

ENV LENOVO_WWAN_UNLOCK_COMMIT=dc9a7eccf72b83e6db528da930cc7f19d6cdd523

# Install FCC-unlock scripts/tools provided by device vendors
ADD --keep-git-dir=true https://github.com/lenovo/lenovo-wwan-unlock.git#${LENOVO_WWAN_UNLOCK_COMMIT} /lenovo-wwan-unlock
WORKDIR /lenovo-wwan-unlock
RUN cp libmbimtools.so /out/usr/lib/ && chmod 444 /out/usr/lib/libmbimtools.so
RUN mkdir -p /out/opt/lenovo/ && \
    cp DPR_Fcc_unlock_service /out/opt/lenovo/ && chmod 544 /out/opt/lenovo/DPR_Fcc_unlock_service
COPY --chown=root:root --chmod=500 fcc-unlock /out/usr/lib/ModemManager/fcc-unlock.d

RUN mkdir -p /var/run/dbus/

COPY mmagent /mmagent
WORKDIR /mmagent
RUN CGO_ENABLED=0 go build -v

FROM scratch

ENTRYPOINT []
WORKDIR /
COPY --from=build /out/ /

COPY mm-init.sh /usr/bin/mm-init.sh
CMD ["/usr/bin/mm-init.sh"]
