FROM lfedge/eve-xen-tools:5f5a4015f2e392b5e8afb76fbc3019d17425e029 as xentools
FROM lfedge/eve-qrexec-lib:95656cc31c191bab92b113db2a18bdfa015fcbe5 as qrexec_lib
FROM lfedge/eve-alpine:6.7.0 as build
ENV BUILD_PKGS gcc make libc-dev linux-headers git pkgconf
RUN eve-alpine-deploy.sh

COPY --from=xentools / /
COPY --from=qrexec_lib / /

RUN git clone https://github.com/QubesOS/qubes-core-qrexec qubes-core-qrexec

RUN mkdir -p /out/usr/bin

WORKDIR /qubes-core-qrexec/daemon

RUN sed -i. -e 's#-Wall##' -e 's#-Wextra##' -e 's#-Werror##'  `find . -name Makefile` 
RUN make BACKEND_VMM=xen
RUN cp qrexec-daemon qrexec-client /out/usr/bin

FROM scratch
ENTRYPOINT []
CMD []
COPY --from=build /out /
