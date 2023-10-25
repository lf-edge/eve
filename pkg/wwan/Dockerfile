# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:29dc7661e9c3dcd0ec7ef9b98d2df58354d85fc0 as build
ENV BUILD_PKGS meson ninja git libc-dev glib-dev make gcc dbus-dev libgudev-dev go
ENV PKGS alpine-baselayout dbus glib udev libgudev
RUN eve-alpine-deploy.sh

ENV MM_VERSION=1.22.0
ENV LIBMBIM_VERSION=1.30.0
ENV LIBQMI_VERSION=1.34.0
ENV LIBQRTR_VERSION=1.2.2
ENV PICOCOM_COMMIT=1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8

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
