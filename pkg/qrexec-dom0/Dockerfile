FROM lfedge/eve-xen-tools:5f5a4015f2e392b5e8afb76fbc3019d17425e029 as xentools

FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS gcc make libc-dev linux-headers git pkgconf
ENV PKGS libc-dev
RUN eve-alpine-deploy.sh
RUN mkdir -p /usr/share/pkgconfig

COPY --from=xentools / /

RUN git clone https://github.com/QubesOS/qubes-core-vchan-xen qubes-core-vchan-xen
RUN git clone https://github.com/QubesOS/qubes-linux-utils qubes-util-linux
RUN git clone https://github.com/QubesOS/qubes-core-qrexec qubes-core-qrexec

WORKDIR /qubes-core-vchan-xen/u2mfn
RUN git checkout 51c9221e0b904001a59d2dac910c28fdc31e18f7
RUN make
RUN cp libu2mfn.so /usr/lib

WORKDIR /qubes-core-vchan-xen/vchan
RUN make -f Makefile.linux
RUN cp libvchan-xen.so /usr/lib
RUN cp vchan-xen.pc /usr/share/pkgconfig
RUN cp libvchan.h /usr/include
RUN cp libvchan-xen.so /usr/lib
RUN cp vchan-xen.pc /usr/share/pkgconfig
RUN cp libvchan.h /usr/include

WORKDIR /qubes-core-qrexec/libqrexec
RUN sed -i. -e 's#-Wall##' -e 's#-Wextra##' -e 's#-Werror##'  `find . -name Makefile`
RUN make BACKEND_VMM=xen INCLUDEDIR=/usr/include LIBDIR=/usr/lib
RUN make install BACKEND_VMM=xen INCLUDEDIR=/usr/include LIBDIR=/usr/lib

RUN mkdir -p /out/usr/bin

WORKDIR /qubes-core-qrexec/daemon
RUN sed -i. -e 's#-Wall##' -e 's#-Wextra##' -e 's#-Werror##'  `find . -name Makefile` 
RUN make BACKEND_VMM=xen
RUN cp qrexec-daemon qrexec-client /out/usr/bin

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /out /
