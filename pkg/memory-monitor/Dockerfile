FROM lfedge/eve-alpine:1f7685f95a475c6bbe682f0b976f12180b6c8726 as memory-monitor-build

ENV BUILD_PKGS gcc musl-dev make linux-headers cmake build-base
ENV PKGS alpine-baselayout musl-utils
RUN eve-alpine-deploy.sh

COPY . /root/memory-monitor

WORKDIR /root/memory-monitor

RUN make dist
RUN chmod +x /root/memory-monitor/dist/memory-monitor-handler.sh

FROM scratch
WORKDIR /
# Create base Linux layout, copying from /out (produced by eve-alpine-deploy.sh)
COPY --from=memory-monitor-build /out/ /
# Copy all the memory-monitor artifacts
COPY --from=memory-monitor-build /root/memory-monitor/dist/memory-monitor /sbin/
COPY --from=memory-monitor-build /root/memory-monitor/dist/memory-monitor-handler.sh /sbin/
COPY --from=memory-monitor-build /root/memory-monitor/dist/memory-monitor.conf /etc/
# COPY --from=memory-monitor-build /root/memory-monitor/dist/sbin.memory-monitor.memory-monitor-handler /etc/apparmor.d/

ENTRYPOINT []
# Run the memory-monitor with the -f flag to run in foreground, so that the container does not exit
# immediately after starting, as LinuxKit does not support running daemon processes.
CMD ["/sbin/memory-monitor", "-f"]



