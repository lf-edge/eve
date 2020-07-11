#!/bin/sh

ctr run --mount type=bind,src=/dev,dst=/dev,options=rbind:rw:rshared    \
        --mount type=bind,src=/proc,dst=/proc,options=rbind:rw:rshared  \
        --mount type=bind,src=/sys,dst=/sys,options=rbind:rw:rshared    \
        --mount type=bind,src=/run,dst=/run,options=rbind:rw:rshared    \
        --device /dev/zfs --privileged --rm -t                          \
        --rootfs /containers/onboot/000-storage-init/lower zfs /bin/sh
