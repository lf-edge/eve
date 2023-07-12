# Direct support of OCI containers on EVE

EVE supports [OCI containers](https://www.opencontainers.org/), which means
that containers from libraries, such as the Docker HUB, can run on EVE as
easily as you would be running a VM.

With projects like [Weave Ignite](https://github.com/weaveworks/ignite)
there has been quite a resurgence of interest in running containers in thin
VMs lately. This trend is followed on EVE. The containerd it's used to set up
the container filesystem as a snapshot, and then it's launched as a VM using the
hypervisor underneath.

## The Idea

We currently provide container support using [containerd](https://containerd.io). We use containerd as far as storing images
and content, creating containers and snapshots. At that point, an entire filesystem and its mounts
are ready, so we can start a VM from that root filesystem.

### Why are these useful at all

Simple: you actually can run containers with it.

### Where does containerd keep images and containers

We use separate containerd instance (user) and start it after vault unlocked to
store all data inside encrypted directory `/persist/vault/containerd`. All work
with preparation of images and containers are done by separate user instance.
