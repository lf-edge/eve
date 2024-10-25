# Notes on developing with containerd

## Snapshotters

Performance of containerd filesystem operations depends a great deal on the choice of a snapshotter. Currently we're using the default overlayfs one, but the choice is vast and constantly evolving. There are a few benchmarks available [here](http://people.redhat.com/mskinner/rhug/q1.2017/Container-Storage-Best-Practices-2017.pdf) and [here](https://integratedcode.us/2016/08/30/storage-drivers-in-docker-a-deep-dive/) but the recommendations are constantly changing based on improvements in the underlying filesystem implementations. Case in point here is ZFS: it used to be great for snapshotters back in 2014, then it got really bad and then it got fixed again around 2020.

At the time of this writeup it is unclear whether we can leverage Docker's overlayfs2 implementation and whether it would give us any real benefits over default overlayfs.

## Tools

containerd structures most of its state in pretty simple formats. The only exception to that rule is how it keeps its metadata around. That state is stored in an embedded [bolt DB](https://github.com/boltdb/bolt) and using [boltbrowser](https://github.com/br0xen/boltbrowser) on `meta.db` is highly recommended when debugging containerd issues.
