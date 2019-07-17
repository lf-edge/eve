# Direct support of OCI containers on EVE

THIS IS A PROTOTYPE -- USE (OR BETTER YET DON'T) AT YOUR OWN RISK.

Now that the disclaimer is out of the way, what we're trying to build here is the direct support for [OCI containers](https://www.opencontainers.org/) on EVE. This means that you will be able to point at a random container on Docker HUB and run it on EVE as easily as you would be running a VM.

With projects like [Weave Ignite](https://github.com/weaveworks/ignite) there has been quite a resurgence of interest in running containers in thin VMs lately. We're very much believers in that trend, but at the same time, since we're currently based on Xen we're using excellent work of Stefano Stabellini
on [Stage1 Xen in rkt](https://github.com/rkt/stage1-xen).

## The Idea

We are currently trying to provide enough of building blocks in EVE to be able to pull off a container support along the lines that [Stefano described in his blog post](https://www.linux.com/blog/xen-project/2017/6/cloud-native-apps-and-security-case-coreos-rkt-and-xen). Admittedly, when everything's said and done, we may actually decide to ditch rkt altogether and stick with runc for example, but for now the rkt itself and stage1 Xen for rkt are there for people to do as they wish.

### The capabilities in EVE

For now, we have added two of the binary artifacts to EVE:

* /usr/sbin/rkt
* /usr/sbin/stage1-xen.aci


### How is it supported

It isn't. It isn't any more supported than /usr/bin/mail that happens to be part of pillar ;-) But you can start playing with it.

### Why are these useful at all

Well, as Stefano describes in his [Stage 1 documentation](https://github.com/rkt/stage1-xen/blob/master/build/fedora/RUNNING_STAGE1_XEN.md#running-stage1-xen) you can actually run containers with it.

You will have to ssh or console logging into EVE, but once you do, here's what you can do:

```bash
ln -s /persist/rkt /var/lib/rkt
rkt --insecure-options=image fetch docker://alpine
rkt run sha512-<ID FROM PREVIOUS LINE> --interactive --insecure-options=image --stage1-path=/usr/sbin/stage1-xen.aci
```

### Why do I have to have that first line anyway

rkt wants to keep its state in /var/lib/rkt but on EVE you want it to be persistent -- hence keep it in /persist/rkt.

As a side note, you can also use rkt --dir /persist/rkt command line option or put that location into [permanent configuration](https://coreos.com/rkt/docs/latest/configuration.html) in /etc.

### What else can I do

This is it for now. But we're hoping to enable it for EVE controlller to run containers as easily as VMs.
