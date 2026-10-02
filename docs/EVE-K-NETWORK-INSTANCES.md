# Connecting Native Kubernetes Workloads to EVE Network Instances

EVE-K (`HV=k`) runs a full k3s cluster on the device, and that cluster is not
limited to applications deployed through the EVE controller. Workloads
deployed directly into Kubernetes — with `kubectl apply`, a Helm chart, or a
GitOps/Rancher-style pipeline — can attach to the same
[Network Instances](NETWORKING.md#network-instance) that controller-managed
applications use. This lets a directly-deployed workload share a Local or
Switch Network Instance with EVE-managed applications: it gets an IP on the
same virtual network, can be reached the same way (including port mapping,
for a Local Network Instance), and can resolve and be reached by other
applications on that Network Instance by name.

## Prerequisites

- The cluster must have native Kubernetes orchestration enabled by the
  controller.
- The Network Instance must be configured as **cluster-wide** — this is a
  property of the Network Instance set by the controller, independent of
  whether any EVE-managed application uses it.

## Attaching a workload

For every cluster-wide Local or Switch Network Instance, EVE automatically
publishes a Kubernetes
[`NetworkAttachmentDefinition`](https://github.com/k8snetworkplumbingwg/network-attachment-definition-client)
named `ni-<network-instance-display-name>` in the `eve-kube-app` namespace.
A workload in any namespace attaches to it the same way it would attach to
any other Multus secondary network: with the standard
`k8s.v1.cni.cncf.io/networks` pod annotation, referencing the
`NetworkAttachmentDefinition` by its cross-namespace name
(`eve-kube-app/ni-<network-instance-display-name>`).

The annotation accepts a comma-separated list of names, or — to use the
fields below — a JSON array. See the
[Multus "how to use" guide](https://github.com/k8snetworkplumbingwg/multus-cni/blob/master/docs/how-to-use.md#run-pod-with-network-annotation)
and the
[Kubernetes Network Custom Resource Definition De-facto Standard](https://github.com/k8snetworkplumbingwg/multi-net-spec)
for the full annotation specification. Only the JSON-array form carries the
optional fields below; the comma-separated shorthand supports only
`[namespace/]name[@interface]`.

| Field | Meaning |
| --- | --- |
| `name` / `namespace` | The `NetworkAttachmentDefinition` to attach to, e.g. `ni-local-ni` in namespace `eve-kube-app`. |
| `interface` | The interface name to use inside the pod (defaults to Multus's own `net1`, `net2`, ... numbering if omitted). |
| `mac` | Request a specific MAC address for this interface. If omitted, EVE computes a stable one, derived from the workload's identity so it stays the same across restarts and node migration. |
| `ips` | Request a specific static IP (Local Network Instance only). The address must be inside the Network Instance's subnet but **outside** its configured DHCP range. |
| `portMappings` | Expose a port of the workload externally through the Network Instance's uplink port — the same mechanism controller-managed applications use for port forwarding. Each entry needs `hostPort`, `containerPort` and `protocol`. |
| `default-route` | Make this Network Instance the workload's default route, instead of the Kubernetes primary network interface (see [Default route](#default-route) below). Only the field's presence matters; the specific address given is not used, since a Network Instance's gateway is fixed by its own configuration. |

Workload identity (and therefore the derived MAC, and best-effort IP) is
based on the workload's namespace and its stable name: a bare Pod's own
name, or a bare `ReplicaSet`'s name for an un-wrapped `ReplicaSet` (i.e.
`replicas: 1`, not managed by a `Deployment`). Recreating a workload under
the same name reuses its networking identity. `Deployment`-managed
workloads and multiple replicas of one `ReplicaSet` are not supported, since
neither has a single stable per-instance identity to derive a MAC from.

## Examples

### A bare Pod with a static MAC and a port mapping

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-namespace
  annotations:
    k8s.v1.cni.cncf.io/networks: |
      [
        {
          "name": "ni-local-ni",
          "namespace": "eve-kube-app",
          "interface": "localni",
          "mac": "02:00:00:00:01:01",
          "portMappings": [
            {"hostPort": 8022, "containerPort": 22, "protocol": "tcp"}
          ]
        }
      ]
spec:
  containers:
    - name: my-app
      image: my-registry/my-app:1.0
```

This Pod gets an interface named `localni` on the `local-ni` Network
Instance, with the requested MAC address, and its port 22 is reachable from
outside through the Network Instance's uplink port at 8022.

### A bare ReplicaSet using a Network Instance as its default route

```yaml
apiVersion: apps/v1
kind: ReplicaSet
metadata:
  name: my-replicated-app
  namespace: my-namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-replicated-app
  template:
    metadata:
      labels:
        app: my-replicated-app
      annotations:
        k8s.v1.cni.cncf.io/networks: |
          [
            {
              "name": "ni-local-ni",
              "namespace": "eve-kube-app",
              "interface": "localni",
              "ips": ["10.11.12.50/24"],
              "default-route": ["10.11.12.1"]
            }
          ]
    spec:
      containers:
        - name: my-replicated-app
          image: my-registry/my-app:1.0
```

This workload requests a specific static IP on `local-ni` and makes that
Network Instance its default route. Replicas can only safely be `1`: every
replica of one `ReplicaSet` would otherwise derive the same identity, and
therefore the same MAC.

## Name resolution

Every application attached to a cluster-wide Network Instance — whether
deployed through the EVE controller or directly into Kubernetes — gets a DNS
record resolvable from anywhere in the k3s cluster:

```text
<app-name>.<namespace>.<network-instance-name>.internal
```

For example, the Pod from the first example above would be resolvable as
`my-app.my-namespace.local-ni.internal`. A shorter alias,
`<app-name>.internal`, is also published whenever that name is unambiguous
across the whole cluster. This lets a directly-deployed workload and an
EVE-managed application on the same Network Instance discover and reach each
other by name, in either direction.

## Default route

By default, a workload's own built-in Kubernetes network interface (the one
every pod gets, regardless of any annotation) remains its default route, so
cluster services such as the Kubernetes API server stay reachable exactly as
for any other pod in the cluster. Requesting `default-route` on a Network
Instance attachment switches the default route to that Network Instance
instead. The Kubernetes API server and the cluster's internal service and
node addresses remain reachable even then, through routes to those specific
destinations that are kept in place regardless of which interface is the
default route.

## See also

- [Network Instance concepts](NETWORKING.md#network-instance)
- [Application connectivity in more detail](APP-CONNECTIVITY.md)
- [EVE-K overview](EVE-K.md)
