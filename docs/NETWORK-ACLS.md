# Network ACLs

An access control list (ACL) consists of one or more access control entries (ACEs) that collectively define
the network traffic profile.
This document describes different types of ACEs, their semantics, limitations and provides few basic examples
for common use-cases.

## Configuration Model

In EVE, ACLs are configured separately for every ECO interface.
Protobuf-modeled configuration model of ACLs can be found in the [fw.proto file](https://github.com/lf-edge/eve-api/tree/main/proto/config/fw.proto).
To control the network traffic between a given ECO and other endpoints within the scope of a given network instance,
add one or more ACEs under the `acls` field of [NetworkAdapter](https://github.com/lf-edge/eve-api/tree/main/proto/config/netconfig.proto).

Every ACE should have a unique non-zero integer ID assigned. Please note that ACE ID should not exceed 24bits.
ACE ID is set in [flowlogs](https://github.com/lf-edge/eve-api/tree/main/proto/flowlog/flowlog.proto) as `aclId` for every flow to show which ACE was applied.
ACE `ID=0` is reserved for a default reject-all rule that implicitly exists at the end of every ACL (even flows whose
packets are rejected are logged).

## ACL Semantics

Every ECO interface is assigned a single separate access control list filtering inbound and outbound traffic
(unless the interface is dedicated to the application (`PhyIoUsageDedicated`), in which case EVE networking
is completely bypassed).
A single entry of ACL, denoted as ACE, consists of a set of matches that use layer 3 and 4 information to select
a subset of the traffic, and a set of actions deciding what to do with the selected traffic. Optionally, it is possible
to limit ACE to only ingress or egress flow direction. By default, ACEs are bi-directional, i.e. applied irrespective
of the flow direction.

For every packet leaving or entering ECO, the list of ACEs assigned to the corresponding interface is traversed
sequentially in the order as configured. The fate of a packet is determined by the first ACE in the list for which
the L3 & L4 packet header fields satisfy every match entry (i.e., matches are ANDed and empty set matches any packet).
Packet can be allowed to continue (`ALLOW` action), dropped (`DROP` action) or mangled - specifically
the destination IP address and port can be rewritten to allow an inbound flow to traverse the NAT of a local network
(`PORTMAP` action).

Apart from stateless filtering, EVE also supports ACL-based traffic limiting based
on the [Token bucket algorithm](https://en.wikipedia.org/wiki/Token_bucket). ACE with the `LIMIT` action
will either accept or reject packet depending on the current state of token buckets to keep the packet rate
of the connection within the configured limits.

Packet that does not match any configured ACE is rejected. In other words, an implicit ACE with an empty set of matches
and the `DROP` action is present at the very end of every ACL. This means that by default application will not be
able to connect to any other deployed application or external endpoint. The only exceptions are local services
provided by EVE, such as DNS server, DHCP server or the internal HTTP server providing cloud-init metadata,
all of which are always accessible to the application (and cannot be blocked).

ACE which is configured without specifying the action will `ALLOW` matched packets. The reasoning is that with
the implicit reject-all ACE at the end of every ACL, it is expected that majority of explicitly configured rules
will be used to list the set of endpoints that application is *allowed* to communicate with.

To summarize, ACL is composed of user-configured ACEs and some implicit rules as follows:

```text
ACL:
  - implicit ACEs to permit DNS, DHCP, internal HTTP, IPv6 Neighbor Discovery
  - explicit ACEs
    - default action (i.e. if not explicitly selected) is to ALLOW
  - implicit drop-all ACE
```

### ACE Match Types

ACE "match" is essentially a filter applied against the address fields from the packet layer 3 and layer 4 headers.
In the [configuration model](#configuration-model), the ACE match is defined as a `(type, value)` pair,
where `type` is an enum, even if defined in the API as a string, while `value` is a string with semantics depending
on the selected `type`. ACE can be configured with no matches (match-all), one match rule, or even multiple matches.
However, multiple matches of the same type inside the same ACE are not allowed. Also, some of the combinations
of different match types are not supported, see [limitations](#limitations).

The currently supported ACE match types are:

* `ip`: `value` should be an IP address of a remote endpoint. The match is satisfied for outbound and inbound flow
  if the destination and the source IP address matches the given value, respectively.
  Can be combined with any other match type to further narrow down the selection criteria.

* `host`: `value` should be a domain name of a remote endpoint. It can be either a fully qualified, or a partially
  qualified domain name (FQDN or PQDN). A packet is matched if it is destined to or originated from an IP address
  that was obtained by a DNS query for that exact domain or any of its subdomains. For example, match of type `host`
  with value `domain.com` will also apply to the endpoint `subdomain.domain.com`.
  Can be combined with other match types except for `eidset` (see [limitations](#limitations)).

* `eidset`: special match type for the overlay network. Matches IPs of all applications deployed in the same network
  as well as all IPs with statically configured DNS entries (under the config field `NetworkInstanceConfig.Dns`).
  For this type, `value` field is not used.
  Can be combined with other match types except for `host` (see [limitations](#limitations)).

* `protocol`: `value` should specify the protocol to match.
  Protocol can be one of `tcp`, `udp`, `icmp`, or `all`, or it can be a numeric value, representing one of these
  protocols or a different one. A protocol name from `/etc/protocols` is also allowed.
  Protocol match can be combined with any other match type (often combined with port numbers).

* `lport`: `value` should be an application *local* port number. For filtering actions, this is the source port for outbound
  traffic and destination port for inbound traffic. For `PORTMAP` action, this represents application port as exposed
  to the external network (i.e., if `<edge-node-ip>:2222` is mapped to `<app-ip>:22`, `lport` refers to `2222`).
  `lport` can be combined with any other match type. It is actually required to combine `lport` and `protocol` inside
  the same ACE. In other words, port without protocol is not valid.

* `fport`: `value` should be a remote endpoint port number (*foreign* port). Used for filtering actions,
  but not for `PORTMAP` (do not confuse with `lport`, which is still used to represent the forwarded port - the forwarded
  port is still considered as local).
  `fport` can be combined with any other match type. It is actually required to combine `fport` with `protocol` inside
  the same ACE. In other words, port without protocol is not valid.

## Limitations

Here is a summary of all limitations of the current ACL implementation:

* even though the configuration model allows to assign multiple actions to a single ACE, the current implementation
  expects only one action and rejects any combination of actions with an error message

* match types `eidset` and `host` are not supported for switch network. This is because these match types work
  in combination with the local DNS service, which is not used for switch networks.

* `host` match type does not work for domains with statically configured DNS entries. Consider using `eidset` instead,
  which, however, matches *all* statically configured domains and also IPs of all apps in the same network.

* flows dropped by ACLs within switch networks are not flow-logged. This is because denied flows which are not routed,
  and only forwarded, get dropped before a conntrack entry is created, which is needed for a flowlog entry
  to be constructed.

* currently `DROP` ACE action is not implemented for local networks. With the implicit reject-all ACE at the end of every ACL,
  it is expected that users will only need to list the set of endpoints that application is *allowed* to communicate with.

* ACL filtering works irrespective of the uplink interface chosen. In other words, it is not possible to have different
  ACL rules depending on which uplink interface is currently being used by a given network instance.

* support for unidirectional filtering is not yet implemented. Instead, all rules (with the exception of `PORTMAP` ACEs)
  are installed as bidirectional. Configuration option for the ACE direction is prepared for the future.

## Examples

This section contains a set of simple ACL configuration examples covering the most common ACL use-cases.
These configuration snippets show only the content of the `acls` field of [NetworkAdapter](https://github.com/lf-edge/eve-api/tree/main/proto/config/netconfig.proto).
The rest of the edge device config is omitted.

### Allow all IPv4 traffic

Please note that `ALLOW` is the default action of an ACE.

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "ip",
          "value": "0.0.0.0/0"
        }
      ]
    }
  ]
}
```

### Allow SSH access to ECO from outside

Assuming that ECO runs an ssh daemon listening on the `tcp` port `22`, we can expose this port on `<edge-node-ip>:2222`
(`2222` is chosen as an example) using a `PORTMAP` ACE:

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "protocol",
          "value": "tcp"
        },
        {
          "type": "lport",
          "value": "2222"
        }
      ],
      "actions": [
        {
          "portmap": true,
          "appPort": 22
        }
      ]
    }
  ]
}
```

### Allow ECO to access specific set of domains (and any of their subdomains)

Please note that multiple `host` matches cannot be combined within the same ACE. Instead, we define multiple ACEs.

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "host",
          "value": "www.github.com"
        }
      ]
    },
    {
      "id": 2,
      "matches": [
        {
          "type": "host",
          "value": "google.com"
        }
      ]
    }
  ]
}
```

### Allow ECO to access a specific remote endpoint

Matches `ip`, `protocol` and `fport` can be all combined under a single ACE.

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "ip",
          "value": "1.1.1.1"
        },
        {
          "type": "protocol",
          "value": "tcp"
        },
        {
          "type": "fport",
          "value": "80"
        }
      ]
    }
  ]
}
```

### Allow ECO to access other ECOs deployed on the same network

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "eidset"
        }
      ]
    }
  ]
}
```

### Limit packet rate between ECO and a remote endpoint

We allow at most 10 packets per second with bursts limited to 30 packets.

```json
{
  "acls": [
    {
      "id": 1,
      "matches": [
        {
          "type": "host",
          "value": "www.google.com"
        }
      ],
      "actions": [
        {
          "limit": true,
          "limitrate": 10,
          "limitunit": "s",
          "limitburst": 30
        }
      ]
    }
  ]
}
```
