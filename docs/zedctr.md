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
|ztools|`zededa/ztools`|[go-provision](https://github.com/zededa/go-provision)|`/`|Interface with cloud controller||
|lisp|`zededa/lisp`|[lisp](https://github.com/zededa/lisp)|[Locator/Identifier Separation Protocol](https://en.wikipedia.org/wiki/Locator/Identifier_Separation_Protocol)|see list [here](#lisp-install)|implementation for mesh networking|custom implementation in [go](https://golang.org) to provide a high performance dataplane. The control plane uses code from the Python reference implementation|
|xen tools|`zededa/xen-tools`|[pkg/xen-tools](../pkg/xen-tools)|`/`|Xen utilities||
|dnsmasq|`zededa/dnsmasq`|[pkg/dnsmasq](../pkg/dnsmasq)|`/usr/sbin/dnsmasq` to `/opt/zededa/bin/dnsmasq`|local DNS server|dnsmasq 2.78 had a bug which we patched. This patch is already upstreamed to 2.80 and should be replaced|
|strongswan|`zededa/strongswan`|[pkg/strongswan](../pkg/strongswan)|`/`|IPSec VPN|Dockerfile has [comment](../pkg/strongswan/Dockerfile#L63-L66), stating that we build custom because of libressl conflict with curl-dev. Should be investigated if this remains an issue|
|gpt tools|`zededa/gpt-tools`|[pkg/gpt-tools](../pkg/gpt-tools)|`/`|Utilities for working with GPT partitioned filesystems. See [here](./UPSTREAMING.md#gpt-tools) for more details on what is in this package|
|watchdog|`zededa/watchdog`|[pkg/watchdog](../pkg/watchdog)|`/usr/sbin` to `/usr/sbin`|[watchdog](https://linux.die.net/man/8/watchdog) daemon to watch for userspace processes and, if they are not providing proper heartbeats, restart the system|Read the section on [restart](#restart) for more information on it.||

In addition, a few local installations are provided as necessary, defined in the [Dockerfile](../pkg/zedctr/Dockerfile). They are:

* `libfdt` via `apk` for `arm64` only
* symlink `/usr/lib/libpcap.so` to `libpcap.so.1`
* generate a host ssh key, configure `/etc/ssh/sshd_config` to permit root login via ssh, and change the ssh root key. See the section on [sshd](#sshd) for more details.
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

* [blink.sh](../pkg/zedctr/rootfs/blink.sh) - test program that will be deleted.
* [sos.sh](../pkg/zedctr/rootfs/sos.sh) - test program that will be deleted.
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

`zedctr` is composed of two different kinds of components:

* services - long-running services that should live for as long as an EVE device is up.
* utilities - tools and utilities that are used primarily by one or more of the long-running services to perform its actions, as well as potentially by a person intervening.

We are exploring the best way to modularize `zedctr`, both in terms of containers for services, as well as separate `domU`s. Specifically, the long-running services in [go-provision](https://github.com/zededa/go-provision) that are started via `device-steps.sh`, may need to be in separate `domU`s.

Under consideration is: where to install the utilities with respect to the services; how services would call the utilities across containers/doms and/or in the same container/dom; how to avoid conflicts among libraries, packages and versions.

Each service also should have its own minimum required capabilities, and should avoid the host PID and networking namespaces, where possible.

For more information, look in the [go-provision repository](https://github.com/zededa/go-provision).

### Restart

A number of services in `zedctr` depend on knowing the state of the device. The known state of the device develops as each of several services evolve together. In other words, the actual good state is emergent. If one of several critical services dies, that state is lost and cannot be reconstructred easily. The simplest solution is to restart _all_ of the services, i.e. reboot the device. Hence, watchdog.

### sshd

We enable sshd to use for administrative access. We enable it in `/etc/ssh/sshd_config`, and then block port 22 using iptables. [go-provision](https://github.com/zededa/go-provision) then enables port 22 when a bona fide request for administrative access is received, and blocks port 22 again when access is ended.

As of now, the access itself involves two weaknesses:

* We generate the host keys at package build time, which means every device has the same host key.
* We authenticate using username/password, with the password built into the image, i.e. known shared secret for every host. Although it is hashed, this is suboptimal.

We are working on a better solution to the above, including, where possible: unique device keys, unique login per device, runtime generation, usage of ECC keys.

