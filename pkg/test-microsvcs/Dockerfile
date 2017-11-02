FROM unikernel/mirage AS mirage
ADD --chown=opam:opam unikernels/mirage/hello /vms/mirage-hello
RUN nohup bash -lc "cd /vms/mirage-hello/ ; opam update ; mirage configure -t xen ; make depend ; make"

FROM scratch
COPY --from=mirage /vms/mirage-hello/hello* /vms/mirage-hello/
ADD unikernels/mirage/README /vms/mirage-hello/
ADD vms/green_grass /vms/green_grass 
