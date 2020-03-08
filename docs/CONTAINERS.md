# Direct support of OCI containers on EVE

THIS IS A PROTOTYPE -- USE AT YOUR OWN RISK.

Now that the disclaimer is out of the way, what we're trying to build here is the direct support for [OCI containers](https://www.opencontainers.org/) on EVE. This means that you will be able to point at a random container on Docker HUB and run it on EVE as easily as you would be running a VM.

With projects like [Weave Ignite](https://github.com/weaveworks/ignite) there has been quite a resurgence of interest in running containers in thin VMs lately. We're very much believers in that trend, but at the same time, since we're currently based on Xen we're using containerd to set up the container filesystem as a snapshot, and then launching it using Xen `xl`.

## The Idea

We currently provide container support using [containerd](https://containerd.io). We use containerd as far as storing images
and content, creating containers and snapshots... and then stop there. At that point, an entire filesystem and its mounts
are ready, so we use Xen to start a domU at that root.

### How is it supported

It isn't. It isn't any more supported than /usr/bin/mail that happens to be part of pillar ;-) But you can start playing with it.

### Why are these useful at all

Simple: you actually can run containers with it.

### Where does containerd keep images and containers

containerd wants to keep its persistent data in `/var/lib/containerd`, and its runtime state
in `/run/containerd` but on EVE you want both to be persistent -- hence we have a symlink pointing to `/persist/`.

### What else can I do

This is it for now. But we're hoping to enable it for EVE controller to run containers as easily as VMs.
