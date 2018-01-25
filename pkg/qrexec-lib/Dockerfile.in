FROM XENTOOLS_TAG as xentools

FROM alpine:3.6	as build

RUN apk add --no-cache \
    gcc \
    make \
    libc-dev \
    linux-headers \
    git


COPY --from=xentools / /

RUN git clone https://github.com/QubesOS/qubes-core-vchan-xen qubes-core-vchan-xen
RUN git clone https://github.com/Zededa/qubes-linux-utils qubes-util-linux

RUN mkdir /out
RUN mkdir -p /out/usr/lib
RUN mkdir -p /out/usr/include
RUN mkdir -p /out/usr/share/pkgconfig

WORKDIR /qubes-core-vchan-xen/u2mfn
RUN make
RUN cp libu2mfn.so /out/usr/lib
WORKDIR /qubes-core-vchan-xen/vchan
RUN make -f Makefile.linux
RUN cp libvchan-xen.so /usr/lib
RUN cp vchan-xen.pc /usr/share/pkgconfig
RUN cp libvchan.h /usr/include
RUN cp libvchan-xen.so /out/usr/lib
RUN cp vchan-xen.pc /out/usr/share/pkgconfig
RUN cp libvchan.h /out/usr/include

WORKDIR /qubes-util-linux/qrexec-lib
RUN make BACKEND_VMM=xen DESTDIR=out/ INCLUDEDIR=/usr/include LIBDIR=/usr/lib
RUN make install BACKEND_VMM=xen DESTDIR=/out/ INCLUDEDIR=/usr/include LIBDIR=/usr/lib


FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /out /