# syntax=docker/dockerfile-upstream:1.5.0-rc2-labs
FROM lfedge/eve-alpine:9fb9b9cbf7d90066a70e4704d04a6fe248ff52bb as build
ENV BUILD_PKGS automake autoconf gettext gettext-dev git pkgconfig \
               libtool libc-dev linux-headers gcc make glib-dev \
               autoconf-archive patch cmake gtk-doc
ENV PKGS alpine-baselayout musl-utils ppp jq glib
RUN eve-alpine-deploy.sh

ENV LIBUBOX_COMMIT=7da66430de3fc235bfc6ebb0b85fb90ea246138d
ENV JSONC_COMMIT=ed54353d8478ccdb8296c33c675662d16d68b40d
ENV INOTIFY_TOOLS_COMMIT=3.20.11.0
ENV PICOCOM_COMMIT=1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8
ENV LIBQMI_COMMIT=1.26.2
ENV LIBMBIM_COMMIT=1.24.2

ADD --keep-git-dir=true https://github.com/json-c/json-c.git#${JSONC_COMMIT} /json-c
WORKDIR /json-c
RUN ./autogen.sh && ./configure && make install

ADD --keep-git-dir=true https://git.openwrt.org/project/libubox.git#${LIBUBOX_COMMIT} /libubox
WORKDIR /libubox
RUN cmake . -DBUILD_LUA=OFF -DBUILD_EXAMPLES=OFF && make install

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/libmbim.git#${LIBMBIM_COMMIT} /libmbim
WORKDIR /libmbim
COPY patches/libmbim/*.patch /tmp/patches/libmbim/
RUN for patch in /tmp/patches/libmbim/*.patch ; do patch -p1 < "$patch" ; done
RUN ./autogen.sh && ./configure --prefix=/usr && make -j "$(getconf _NPROCESSORS_ONLN)" && make install

ADD --keep-git-dir=true https://gitlab.freedesktop.org/mobile-broadband/libqmi.git#${LIBQMI_COMMIT} /libqmi
WORKDIR /libqmi
COPY patches/libqmi/*.patch /tmp/patches/libqmi/
RUN for patch in /tmp/patches/libqmi/*.patch ; do patch -p1 < "$patch" ; done
RUN ./autogen.sh --without-udev && ./configure --prefix=/usr --without-udev --enable-mbim-qmux && make -j "$(getconf _NPROCESSORS_ONLN)" && make install

ADD --keep-git-dir=true https://github.com/inotify-tools/inotify-tools.git#${INOTIFY_TOOLS_COMMIT} /inotify-tools
WORKDIR /inotify-tools
RUN ./autogen.sh && ./configure --prefix=/usr && make -j "$(getconf _NPROCESSORS_ONLN)" && make install

ADD --keep-git-dir=true https://github.com/npat-efault/picocom.git#${PICOCOM_COMMIT} /picocom
WORKDIR /picocom
# Need this patch to build with musl: https://github.com/npat-efault/picocom/commit/1acf1ddabaf3576b4023c4f6f09c5a3e4b086fb8
RUN make -j "$(getconf _NPROCESSORS_ONLN)" && strip picocom && cp picocom /usr/bin/

RUN strip /usr/bin/*cli /usr/libexec/*proxy /usr/lib/libmbim*.so.* /usr/lib/libqmi*.so.* /usr/lib/libinotifytools*.so.*

# second stage (new-ish Docker feature) for smaller image
FROM scratch

ENTRYPOINT []
WORKDIR /
COPY --from=build /out/ /
COPY --from=build /usr/bin/qmicli /usr/bin/mbimcli /usr/bin/inotify* /usr/bin/picocom /bin/
COPY --from=build /usr/lib/libmbim*.so.[0-9] /usr/lib/libqmi*.so.[0-9] /usr/lib/
COPY --from=build /usr/lib/libinotifytools*.so.[0-9] /usr/lib/
COPY --from=build /usr/libexec/*proxy /usr/libexec/
COPY usr/ /usr/
COPY etc/ /etc/
CMD ["/usr/bin/wwan-init.sh"]
