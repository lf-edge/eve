# zedctr

[zedctr](../pkg/zedctr), or "Zededa Container", is a catch-all container for many services that run as persistent services on the live rootfs. It is defined in the `services` section of the [rootfs.yml config file](../images/rootfs/yml). Ideally, most of these services would be separated out, each into its own service.

This document describes the structure of `zedctr`, what services it provides and how it is built.

## Location

`zectr` is built in [pkg/zedctr](../pkg/zedctr) in this repository, although it includes certain outside packages when it is built. The resultant package is an OCI image named `zededa/zedctr`, which may be pushed to the image registry.

## Runtime Config

When run in the live rootfs, it runs with maximal capabilities, essentially as if it is running outside a container. These runtime capabilities are defined in [build.yml](../pkg/zedctr/build.yml).

* It has `capabilities: all`, which should be split into individual capabilities listed for each service.
* It has `pid: host`, working in the same PID namespace as the host.
* It has `net: host`, working directly in the host networking namespace.
* It mounts most of the root filesystem into its own namespace, including `/:/hostfs`. The mounts are listed below:

```yml
  binds:
    - /lib/modules:/lib/modules
    - /dev:/dev
    - /etc/resolv.conf:/etc/resolv.conf
    - /run:/run
    - /var/config:/config
    - /var/log:/var/log/dom0
    - /:/hostfs
```

## Components

The image `zededa/zedctr` is built from its [Dockerfile](../pkg/zedctr/Dockerfile), which is generated from its [Dockerfile.in](../pkg/zedctr/Dockerfile.in), with the relevant image names and tags patched in.

It is built from the following packages, installed into the following locations:

|Package|Image|Source|Install|Purpose|Comments|
|---|---|---|---|---|
|ztools|`zededa/ztools`|[go-provision](https://github.com/zededa/go-provision)|`/`|Interface with zedcloud||
|lisp|`zededa/lisp`|[lisp](https://github.com/zededa/lisp)|[Locator/Identifier Separation Protocol](https://en.wikipedia.org/wiki/Locator/Identifier_Separation_Protocol)|see list [here](#lisp-install)|implementation for mesh networking|custom implementation in [go](https://golang.org), as the reference implementation is in python and has unneeded services|
|xen tools|`zededa/xen-tools`|[pkg/xen-tools](../pkg/xen-tools)|`/`|Xen utilities||
|dnsmasg|`zededa/dnsmasq`|[pkg/dnsmasq](../pkg/dnsmasq)|`/usr/sbin/dnsmasq` to `/opt/zededa/bin/dnsmasq`|local DNS server|Unclear why we need a local build|
|strongswan|`zededa/strongswan`|[pkg/strongswan](../pkg/strongswan)|`/`|IPSec VPN|Dockerfile has [comment](../pkg/strongswan/Dockerfile#L63-L66), stating that we build custom because of libressl conflict with curl-dev. Should be investigated if this remains an issue|
|gpt tools|`zededa/gpt-tools`|[pkg/gpt-tools](../pkg/gpt-tools)|`/`|Utilities for working with GPT partitioned filesystems. See [here](./UPSTREAMING.md#gpt-tools) for more details on what is in this package|
|watchdog|`zededa/watchdog`|[pkg/watchdog](../pkg/watchdog)|`/usr/sbin` to `/usr/sbin`|[watchdog]() daemon to watch for userspace processes and, if they are not providing proper heartbeats, restart the system|Unclear why we need to restart the system vs restarting zombie processes, a la systemd/runit/supervisord/etc.|

In addition, a few local installations are provided as necessary, defined in the [Dockerfile](../pkg/zedctr/Dockerfile). They are:

* `libfdt` via `apk` for `arm64` only
* symlink `/usr/lib/libpcap.so` to `libpcap.so.1`
* generate a host ssh key, configure `/etc/ssh/sshd_config` to permit root login via ssh, and change the ssh root key. It is unclear why we are doing this for several reasons:
    * We are generating the root password at package build time, storing secrets in a static OCI image. 
    * We are generating the ssh host key at package build time, causing all hosts to have the same ssh host key.
    * We are allowing root login via ssh
* copy the local [pkg/zedctr/rootfs](../pkg/zedctr/rootfs/) into the image at `/`
* Set the `CMD /init.sh`

#### lisp-install

lisp files are copied as follows:

```
COPY --from=lisp /lisp/lisp-ztr /opt/zededa/bin/
COPY --from=lisp /lisp /opt/zededa/lisp/
COPY --from=lisp /usr/bin/pydoc /usr/bin/smtpd.py /usr/bin/python* /usr/bin/
COPY --from=lisp /usr/lib/libpython* /usr/lib/libffi.so* /usr/lib/
COPY --from=lisp /usr/lib/python2.7 /usr/lib/python2.7/
```

#### zedctr/rootfs

[zedctr/rootfs](../pkg/zedctr/rootfs) is a small group of files that are installed in the root to `/` of the `zedctr` container. This document will not list every file, but will give the general purposes.

* [blink.sh](../pkg/zedctr/rootfs/blink.sh) - appears to be a simple utility to exercise `/dev/sda` by copying 22 blocks of 4M to `/dev/null`, a process that should take about 200ms, then sleeps 200ms, repeating 3 times, then sleeping 1200ms, then repeating. Its usage is unknown.
* [sos.sh](../pkg/zedctr/rootfs/sos.sh) - similar to blink, but an SOS pattern instead. Its usage is unknown.
* [dhcpcd.conf](../pkg/zedctr/rootfs/dhcpcd.conf) - dhcp client daemon config file. Unclear why it is in `/` and not under `/etc`.
* [init.sh](../pkg/zedctr/rootfs/init.sh) - entrypoint command for the `zedctr` container. Starts with a comment, "This *really* needs to be replaced with tini+monit ASAP." It functions as a process launcher. It does the following:
    * start sshd
    * start crond for logrotate
    * disable hardware TCP offloading
    * set the nameserver to `8.8.8.8`
    * start Xen with logging defined
    * runs optional `/opt/zededa/bin/device-steps.sh`
    * follow tails (`tail -f`) all files in `/var/log/*.log` as well as `/dev/null`, apparently to ensure it never exits, terminating the container.
* [etc/](../pkg/zedctr/rootfs/etc/) - various config files for `logrotate` and `nsswitch`
* [config/](../pkg/zedctr/rootfs/config) - empty directory, required for runtime

### Modularization Path

This should be modularized, with each one its own package and service in the runtime. Each of the listed services should be its own container, managed by containerd (as is normal when listed in linuxkit `services:`). Each should also have its own minimum required capabilities, and should avoid the host PID and networking namespaces, where possible.

This section lists inter-dependencies that exist between services:

* **TO FILL IN**


