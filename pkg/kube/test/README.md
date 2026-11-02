# pkg/kube/test

Scripts in this directory are **not installed** into the kube container image via the
Dockerfile. They are development and verification tools intended to be bind-mounted into
a running kube container on demand:

```sh
eve exec kube sh -c "mount --bind /host/path/to/test/<script>.sh /usr/bin/<script>.sh && <script>.sh"
```

or copied in for a one-shot run during cluster debugging.

## Tools

| Script | Purpose |
| ------ | ------- |
| `kube-test-longhorn-pvc-size.sh` | Compares Longhorn ground-truth PVC sizes (live data + snapshot chain) against EVE's pubsub-reported values in `VolumeStatus.CurrentSize` and `KubeClusterInfo.AllocatedBytes`. Exits 0 if all volumes are within the configurable drift tolerance, 1 otherwise. |

## Usage

```sh
# Basic — 10% drift tolerance (default)
kube-test-longhorn-pvc-size.sh

# Stricter tolerance with per-snapshot detail
kube-test-longhorn-pvc-size.sh -t 5 -v

# Custom Longhorn namespace
kube-test-longhorn-pvc-size.sh -n longhorn-system
```

Requires `kubectl`, `jq`, and `awk` in the container (`kubectl` and `jq` are present in
the kube image; `awk` is provided by busybox).
