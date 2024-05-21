# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs

# Copyright (c) 2023 Zededa, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as build
ENV BUILD_PKGS meson ninja git libc-dev glib-dev make gcc dbus-dev libgudev-dev go
ENV PKGS alpine-baselayout dbus glib udev libgudev
RUN eve-alpine-deploy.sh

ENV MM_VERSION=1.22.0
ENV LIBMBIM_VERSION=1.30.0
ENV LIBQMI_VERSION=1.34.0
ENV LIBQRTR_VERSION=1.2.2
ENV PICOCOM_COMMIT=1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8
ENV LENOVO_WWAN_UNLOCK_COMMIT=058d555e79314b6c2afca44d30986744819e8160

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/libqrtr-glib.git#${LIBQRTR_VERSION} /libqrtr
WORKDIR /libqrtr
RUN meson build --buildtype=release --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib \
          -Dgtk_doc=false -Dintrospection=false && \
    ninja -C build && \
    ninja -C build install

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/libmbim.git#${LIBMBIM_VERSION} /libmbim
WORKDIR /libmbim
RUN meson build --buildtype=release --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib \
          -Dbash_completion=false -Dintrospection=false -Dman=false && \
    ninja -C build && \
    ninja -C build install

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/libqmi.git#${LIBQMI_VERSION} /libqmi
WORKDIR /libqmi
RUN meson build --buildtype=release --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib \
          -Dbash_completion=false -Dintrospection=false -Dman=false && \
    ninja -C build && \
    ninja -C build install

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/ModemManager.git#${MM_VERSION} /mm
WORKDIR /mm
RUN meson build --buildtype=release --prefix=/usr --sysconfdir=/etc --libdir=/usr/lib \
          -Dmbim=true -Dqmi=true -Dbash_completion=false -Dintrospection=false -Dpolkit=no \
          -Dsystemd_suspend_resume=false -Dsystemdsystemunitdir=no -Dsystemd_journal=false && \
    ninja -C build && \
    ninja -C build install

ADD --keep-git-dir=true https://github.com/npat-efault/picocom.git#${PICOCOM_COMMIT} /picocom
WORKDIR /picocom
# Need this patch to build with musl: https://github.com/npat-efault/picocom/commit/1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && strip picocom && cp picocom /usr/bin/

# Install FCC-unlock scripts/tools provided by device vendors
ADD --keep-git-dir=true https://github.com/lenovo/lenovo-wwan-unlock.git#${LENOVO_WWAN_UNLOCK_COMMIT} /lenovo-wwan-unlock
WORKDIR /lenovo-wwan-unlock
RUN cp libmbimtools.so /out/usr/lib/ && chmod 444 /out/usr/lib/libmbimtools.so
RUN mkdir -p /out/opt/lenovo/ && \
    cp DPR_Fcc_unlock_service /out/opt/lenovo/ && chmod 544 /out/opt/lenovo/DPR_Fcc_unlock_service
COPY --chown=root:root --chmod=500 fcc-unlock /out/usr/lib/ModemManager/fcc-unlock.d

RUN strip /usr/bin/*cli /usr/libexec/*proxy

RUN mkdir -p /var/run/dbus/

COPY mmagent /mmagent
WORKDIR /mmagent
RUN CGO_ENABLED=0 go build -v

FROM scratch

ENTRYPOINT []
WORKDIR /
COPY --from=build /out/ /

# Only for troubleshooting purposes.
COPY --from=build /usr/bin/mmcli /usr/bin/qmicli /usr/bin/mbimcli /usr/bin/picocom /usr/bin/

COPY --from=build /usr/libexec/*proxy /usr/libexec/
COPY --from=build /usr/sbin/ModemManager /usr/bin/
COPY --from=build /mmagent/mmagent /usr/bin/

COPY --from=build /usr/lib/libqrtr*.so.[0-9] /usr/lib/
COPY --from=build /usr/lib/libmbim*.so.[0-9] /usr/lib/libqmi*.so.[0-9] /usr/lib/
COPY --from=build /usr/lib/libmm*.so.[0-9] /usr/lib/

COPY --from=build /etc/ModemManager /etc/ModemManager
COPY --from=build /usr/lib/ModemManager /usr/lib/ModemManager
COPY --from=build /usr/share/ModemManager /usr/share/ModemManager

COPY --from=build /etc/dbus-1 /etc/dbus-1
COPY --from=build /usr/share/dbus-1 /usr/share/dbus-1
COPY --from=build /lib/udev/rules.d /lib/udev/rules.d

COPY mm-init.sh /usr/bin/mm-init.sh
CMD ["/usr/bin/mm-init.sh"]
