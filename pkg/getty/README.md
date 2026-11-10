# getty

EVE's build of [linuxkit's getty package](https://github.com/linuxkit/linuxkit/tree/master/pkg/getty)
on eve-alpine. The files under `etc/` and `usr/` are linuxkit's (Apache-2.0),
unchanged; only the base image and the package list differ (see the
Dockerfile). It runs a getty on every console named on the kernel command
line, as `/etc/init.d/001-getty` of the rootfs, and pillar's console handling
relies on that file being present.
