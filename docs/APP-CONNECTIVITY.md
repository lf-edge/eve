# Application Connectivity

Edge applications often require network connectivity to access other applications or some
external network endpoints. EVE provides different means of connectivity, varying in properties,
feature-sets and performance considerations.

## Application network interfaces

Network connectivity is enabled for an application by configuring one or more network adapters.
These consists of [virtual network interfaces](#virtual-network-interfaces), connecting
application with [network instances](#network-instances), and directly assigned
[physical NIC](#physical-network-ports) or [SR-IOV virtual functions](#sr-iov-vfs).
The order of network adapter configurations inside `AppInstanceConfig` matters, because this
is the same order at which these network adapters will be presented to the application by the
Virtual Machine Manager (VMM).
This order is reflected in the PCI addresses of the adapters. It is important to note that VIFs
and direct assignments are configured in two separate lists. The VMM is configured to present
VIFs first, adhering to their configured order, followed by direct assignments in their respective
order. User cannot enforce direct assignment to appear before VIF.

### Physical network ports

EVE allows applications to directly access physical NICs and avoid any virtualization overhead.
This is especially useful for applications that require high-performance network connectivity.
Another use-case is when EVE does not provide suitable driver for the NIC (or the driver is
proprietary and for licensing reasons cannot be shipped with EVE). In such case, the application
can have the driver installed and use the NIC directly.

The following hypervisor capabilities are used to manage IOMMU-based device assignments
to application domains:

* [Xen PCI Passthrough](https://wiki.xenproject.org/wiki/Xen_PCI_Passthrough) for Xen
* [QEMU/VFIO Passthrough](https://wiki.archlinux.org/index.php/PCI_passthrough_via_OVMF) for KVM

### SR-IOV VFs

SR-IOV NIC VFs (virtual functions) combine the resource-sharing advantages of virtual interfaces
with performance benefits of direct assignments.
In this case, the virtualization of the physical resource (NIC) is done by the hardware itself.
EVE OS manages the PF (physical function) inside the host, creates virtual functions based
on the configuration (device model), and performs direct assignment of these VFs into applications
(using the very same technologies as for physical ports).

The main difference between directly assigned VF and a physical port from the application
perspective, is that virtual function requires a different "VF" driver variant to operate
the network adapter.

Please beware that so far only Intel I350 NIC with `igb`/`igbvf` drivers was tested and verified
to work with EVE.

### Virtual network interfaces

Virtual network interface (abbreviated to VIF) is a pair of network devices. The first of these
(the frontend by the [xen terminology](https://wiki.xenproject.org/wiki/Xen_Networking))
will reside in the guest (application) domain while the second (the backend in Xen, TAP with
kvm/qemu) will reside in the host (Dom0 for xen).
This virtual link is created in a cooperation between EVE and the hypervisor to connect
application with a [network instance](#network-instances).

By default, VIF is a paravirtualized VirtIO device. A VM application therefore has to have
a VirtIO driver installed to be able to connect to network instances. Container applications
are running inside a VM prepared by the EVE, with the driver already included.
Without HW-assisted virtualization capabilities, EVE will fallback to an emulated e1000 NICs,
with higher CPU overhead and worse performance. The upside is that the e1000 driver emulates
a widely used Intel 82540EM network interface card, making it compatible with a broad range
of operating systems that include built-in support for this hardware.

On the host (EVE) side, VIF has interface name `nbu<vif-num>x<app-num>` and is enslaved
under the bridge of the corresponding network instance. On the guest side, the VIF
interface name will be `eth<index>` for a container app, or it will completely depend
on the OS of a VM application and its interface naming rules.

IP addresses are given to application VIFs using DHCP with a limited lease time. This means
that a DHCP client should be running inside the guest VM, requesting IP addresses on boot
and anytime a lease times out. For container apps this is taken care of by the init script
of the wrapper VM prepared by EVE. When app container starts, virtual interfaces are already
initialized and have IP addresses assigned.
VM applications are required to perform DHCP requests themselves. Cloud-init is commonly used
to instruct the app OS to perform DHCP on selected network interfaces.

Data-plane of VIFs spans across both guest and host network stacks. Packet sent from an application
is routed by the guest OS (Alpine Linux for container apps) and transmitted across a VIF
into the host network stack. It arrives via TAP/xen-backend and gets forwarded to the NI bridge.
Next, ACLs implemented using iptables are applied and the packet is either allowed to continue
or gets dropped. If [flow logging](#flow-logging) is enabled, this is done by marking the packet with
"allow" or "drop" mark. Based on the mark and the src/dst addresses, IP rules either send the packet
into the dummy blackhole interface (dropped), or route the packet according to the NI routing
table. If flow logging is disabled, packet is allowed or dropped immediately using iptables
actions.
If the packet is allowed and the destination is external, packet will be transmitted out through
one of the network ports used by the network instance.
Note that if NI is switch (L2 only), packet will be just forwarded through one of the ports,
not routed.
If the packet is allowed and the destination is another app (inside the same NI), packet's dst
MAC address will be set to the dst app MAC, and it will be forwarded again through the same bridge
into the corresponding VIF. Finally, the packet is transmitted from the host network stack into
the guest network stack of the destination application, where it will be processed for local
delivery. The diagram below depicts all these packet-flow stages:

![packet-flow](./images/eve-app-packet-flow.png)

Packet received from outside and destined to an application is received via a network port
and matched against active flows tracked by the [Linux connection tracking subsystem](https://conntrack-tools.netfilter.org/manual.html).
In case of an app-initiated flow and a local NI (L3, with NAT), inbound packets will match
an existing contract entry and the NATed dst IP address and port number will be reversed back
to the application src address. In case of an outside-initiated flow, apps connected over local NIs
can only be accessed over port forwarding rules. If a rule is matched, dst IP and port are
D-NATed to the application address.
Next, ACLs are applied and the packet is either allowed to continue or gets dropped.
If [flow logging](#flow-logging) is enabled, this is done by marking the packet with "allow"
or "drop" mark. Based on the mark and the dst address, IP rules either send the packet
into the dummy blackhole interface (dropped), or route the packet according to the NI routing
table. If flow logging is disabled, packet is allowed or dropped immediately using iptables
actions.
If the packet is allowed, it will match the connected route of the NI bridge and gets forwarded
via the bridge and the VIF into the application.
Note that in case of a switch NI (L2 only), D-NAT and routing operations are not performed
and inbound packets are simply forwarded from the input port, through the bridge and VIF into
the application (still the ACLs do apply).
The diagram below depicts all these inbound packet-flow stages:

![packet-flow-inbound](./images/eve-app-packet-flow-inbound.png)

## Network instances

Network instance (NI for short) is a virtual switch deployed inside an edge-device,
allowing applications (virtual machines or containers) to communicate with one another over
a virtual network. Network instance represents a single network segment. Depending on the type
and configuration, it is either internal to the edge-node or an extension of an external network
segment.

Network instances are a feature of the EVE OS host networking build using various software tools.
Applications connect to network instances using [virtual network interfaces](#virtual-network-interfaces).
Directly assigned physical network ports or SR-IOV VFs bypass the host networking, thus cannot
be part of network instances. Apart from VIFs, network instance can be connected to one or more
physical or logical (e.g. VLAN) [network ports](#network-instance-ports) (inside the host) and
provide applications external connectivity.

It is possible to deploy any number of network instances onto the same device. Applications
connected to the same network instance will be able to talk to each other without having to use
any physical network equipment. Reachability between applications in different network instances
will be possible only if there is a routed/forwarded path between these network instances across
physical ports and their networks. Application is allowed to be connected to multiple network
instances and even to have multiple VIFs inside the same NI. In such cases, it is important to have
the routing inside the app configured correctly to ensure that a given flow uses the right interface
(see [Network Instance IP routing](#application-ip-routing)).

However, even if the network topology provides a path from one application to another or to an external
endpoint, a given flow must still be explicitly allowed by user-configured L3/L4 [ACLs](NETWORK-ACLS.md).
ACLs are configured per application VIF, separately for inbound and outbound directions.
By default, application is not allowed to send or receive any traffic with the exception
for the DHCP and DNS traffic (i.e. the implicit default rule is to drop everything).

Network instances do not have to be used at all. Applications can simply only use direct assignment
of physical NICs or SR-IOV VFs. The downside of direct assignments is less flexibility and less
efficient physical resource utilization. Network instances allow to share physical network ports
or even to avoid using them when not necessary. The downside of NI is an extra overhead introduced
to the data-plane from the virtualization. Performance-sensitive applications should prefer
direct assignments and use NIs only for e.g. management traffic.

Presently, EVE provides only 2 simple kinds of network instances: *Local* and *Switch*.
The idea is that anything more advanced (VPN, network mesh, etc.) should be provided
by an application.

### Local Network Instance

Local network instance uses a (user-selected) private IP subnet. Traffic flowing between
applications and external endpoints is being routed (one hop inside the host) and NATed.
This means that packets with IP addressed from the NI private IP subnet never appears outside
the edge device. Same is true for application MAC addresses due to the routing hop.
For this reason it is more common to let EVE generate MAC address for an application
than to configure one statically.

The use of NAT prevent applications from being directly accessible from outside. User must
configure port forwarding rules (for TCP or UDP) to allow an external endpoint to initiate
communication with an application. These rules are configured as part of [network ACLs](NETWORK-ACLS.md).

Meanwhile, applications connected to the same Local NI can communicate with each other directly,
they are on the same network segment after all. However, by default EVE grants applications DHCP
leases with /32 IP addresses (even if network prefix of the NI is something else). This is then
accompanied by a link-local route for the whole subnet, with gateway pointing to the IP address
assigned to the NI bridge created inside the host. This seemingly strange configuration makes
traffic going from one app to another routed through the host (even though it could be just forwarded).
We do this because it better enforces the use of ACLs and makes flow logging easier.
The all-ones subnet netmask can be problematic to some applications, however. In such case,
it is possible to disable it (and use proper subnet mask) with `debug.disable.dhcp.all-ones.netmask`.

For Local network instances, EVE runs basic network services like DHCP or DNS internally.
Every application VIF is either automatically allocated IP address or a user-configured IP
address is used. In both cases, DHCP server deployed for the NI is configured with a host entry
mapping the VIF MAC address (generated or user-defined) to this IP address. EVE will monitor
DHCP traffic and detect when the application finally asks for this IP address using its DHCP
client. Only then the VIF IP address is published to the controller as part of the Info message.

DHCP server also inform application about the DNS server(s) to use. By default, this will only
include the DNS server run be EVE for the NI, listening on the NI bridge IP. In fact, DHCP and
DNS servers are deployed by EVE as the same [dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html)
process. User is able to avoid EVE's DNS server from being used and provide its own list of DNS
servers for applications.

Additionally, DHCP server can be used to [propagate IP routes](#application-ip-routing)
as well as IP addresses of NTP servers to applications. User is able to configure one NTP server
IP per local network instance. This is then merged with NTP server(s) set for NI ports
(received from external DHCP servers or configured by the user), and propagated together
to the application using the DHCP option 42 (56 in DHCPv6).

DNS server which EVE provides for every Local NI allows resolution of application names
to their IP addresses. This is very handy when applications need to talk to each other but
cannot predict how EVE will allocate IP addresses between them.
Every other name resolution request is just forwarded to DNS servers associated with
the NI ports (received from external DHCP servers or configured by the user).

Applications connected to local NI are also provided with access to Metadata HTTP server,
running on local-only IP address 169.254.169.254. This can be used by applications
to retrieve cloud-init configuration, obtain information from EVE (e.g. device UUID,
hostname, external IP address) or to download [patch envelopes](PATCH-ENVELOPES.md).
More information about metadata server can be found in [ECO-METADATA.md](ECO-METADATA.md).

#### IPAM

Every Local Network Instance must be configured with an IPv4 network subnet and an IP
range within this subnet for automatic IP allocations. Host IP addresses from this subnet
that do not fall within the IP range are available for manual assignment.

Whether an IP address is selected manually or dynamically assigned by EVE from the configured
IP range, an internal DHCP server is used to distribute these IP addresses to applications.
Container applications are deployed inside a "shim VM", which EVE prepares, ensuring that
a DHCP client is running for every virtual interface connected to a network instance
This guarantees that the IP address is received and applied before the application starts.
In contrast, VM applications are responsible for starting their own DHCP client and applying
the received IP addresses.

Regardless of the application type, EVE does not automatically assume that the allocated
IP address is actually in use. Instead, it monitors the set of IP leases granted by the internal
DHCP server and updates the set of application IP addresses in the published info messages
accordingly.

### Switch Network Instance

Switch Network Instance is a simple L2-only bridge between connected applications and
(optionally) one or more network ports. Traffic is only forwarded by the host network stack.
This allows applications to directly access external endpoints and vice-versa.
Switch network can be configured without port (i.e. as air-gapped), in which case it is merely
a bridge between application VIFs.

EVE does not run DHCP server for Switch NI. Instead, external DHCP server from the port's
network can be configured by the user to provide IP addresses to applications. In case of air-gap
switch NI, one of the applications can run DHCP server for the network.

Application MAC addresses can be either statically user-configured, or generated by EVE.
Since multiple edge devices running EVE can connect to the same network segment via switch NIs,
the MAC address generator will apply a hash function to the app UUID in an attempt to produce
MAC address unique across the entire fleet of devices (and not just within one device).

Despite Switch NI operating only at the L2 layer, the L3/L4 [network ACLs](NETWORK-ACLS.md)
are still supported and must be configured to allow anything beyond just DNS and DHCP to pass.
Since there is no NAT between applications and external endpoints, properly configured
inbound ACL rules are that much more important.

A metadata HTTP server is run for a switch network instance only if it has a port attached
that has an IP address.

#### IP address detection

Unlike a Local Network Instance, a switch network instance is configured without any IP
configuration, and EVE does not run an internal DHCP server. Instead, if IP connectivity
is required, IP addresses must be assigned statically within the connected applications
or provided by an external DHCP server or another application offering DHCP services.

Since EVE is not in control of IP address allocations and leases, it must monitor application
traffic to learn which IP addresses are being used and report this information to the controller.

In the case of an external DHCP server (IPv4), EVE captures the DHCPACK packet from the server,
which confirms the leased IP address. Because EVE manages MAC address allocations, it knows
the MAC address of every application's virtual interface (VIF). It can then map the CHADDR
(Client Hardware Address) attribute to the corresponding application VIF and learn the assigned
IP address from the YIADDR (your, i.e. client, IP Address) attribute. Additionally, EVE reads
the DHCP option 51 (Lease Time), if available, to determine how long the leased IP address
is valid. If EVE does not observe an IP renewal within this period, it assumes that the IP address
is no longer in use and reports this change to the controller.

For statically assigned IPv4 addresses, EVE captures both ARP reply and request packets to learn
the application VIF IP assignment from either Sender IP + MAC or Target IP + MAC attribute
pairs. Since ARP cache entries have a limited lifetime — typically around 2 minutes — EVE expects
to see at least one ARP packet for every assigned IP within a 10-minute window (this is not
configurable). If no ARP packet is observed within this period for a previously detected IP
assignment, EVE assumes that the IP address has been removed and reports this change to
the controller. EVE also captures ARP packets for IP addresses configured via DHCP, but these
are ignored as the information from the previously captured DHCPACK takes precedence.
Note that ARP-based IP detection is enabled by default but can be disabled by setting
the configuration item `network.switch.enable.arpsnoop` to `false`. Change in this config
options will apply to already deployed switch network instances.

For an external DHCPv6 server, EVE captures DHCPv6 REPLY messages. It learns the target MAC
address from the DUID option (Client Identifier, option code 1), while the IPv6 address
and its valid lifetime are provided by the IA Address (option code 5).

To learn IPv6 addresses assigned using SLAAC (Stateless Address Auto Configuration),
EVE captures unicast ICMPv6 Neighbor Solicitation messages. These are sent from the interface
with the assigned IPv6 address to check if the address is free or already in use by another
host — a process known as Duplicate Address Detection (DAD). The ICMPv6 packet sent to detect
IP duplicates for a particular VIF IP will have the VIF MAC address as the source address
in the Ethernet header. EVE uses this, along with the "Target Address" field from the ICMPv6
header, to identify the assigned IPv6 address.

EVE is capable of detecting multiple IPs assigned to the same VIF MAC address. This is commonly
seen when applications use VLAN sub-interfaces, which share the parent interface's MAC address.

### Network Instance Ports

Network instances can be configured with one or more network adapters, which will be used
to provide external connectivity. The network adapter can be a physical network port
(e.g., `eth0`) or a logical network adapter on top of physical ports (e.g., a VLAN
sub-interface or a LAG). In addition to selecting a specific adapter for NI by referencing
its unique logical label, it is also possible to either use a predefined shared label
or define a custom shared label selecting multiple ports for a network instance.
Predefined shared labels are:

* `all`: assigned to every device network port
* `uplink`: assigned to every management port
* `freeuplink`: assigned to every management port with zero cost

Network instance (both Local and Switch) can be configured without any port. In this case,
the network is "air-gapped", meaning that it is not reachable from outside and, likewise,
it will not provide external connectivity to the applications. Air-gap NIs are used only
to connect applications running on the same edge device.

### Multi-port Switch Network Instance

A switch network instance with multiple ports enables the following:

* Bridging multiple switches while adding redundant links. STP is used to prevent bridge loops.
* Connecting end-devices (e.g. sensors) to the same Layer 2 segment as applications running
  on the edge node.

The user can use a shared label to select multiple network ports for a switch network
instance. For a port to be eligible for bridging with other ports, it must be configured
as app-shared and with DHCP passthrough - meaning it should not have a static IP address
or run a DHCP client.

EVE automatically runs the traditional IEEE 802.1D Spanning Tree Protocol (STP) for bridges
with multiple ports to prevent bridge loops and the broadcast storms that would result from
them. Users can enable BPDU guard on ports intended to connect end-devices, which are not
expected to participate in the STP algorithm. Application VIFs always have BPDU guard enabled.

### VLAN-aware Switch Network Instance

By default, a Switch Network Instance does not apply any special handling to VLANs.
It operates like a traditional Layer 2 switch, forwarding traffic based solely on MAC
addresses without considering VLAN tags. This means that the bridge forwards both tagged
and untagged frames without altering or interpreting the VLAN tags. As a result, any VLAN-tagged
traffic will pass through the bridge unchanged, and no VLAN filtering or segregation will
occur unless explicitly configured.

To enable VLAN filtering and make the Switch Network Instance VLAN-aware, the user must
designate at least one application VIF or NI port as a VLAN Access Port for a specific
VLAN ID. Multiple applications connected to the same Switch Network Instance can either
access the same VLAN - allowing direct communication with one another - or be separated
into different virtual network segments. In the EVE API, access VLANs are assigned to NI
ports within the NetworkInstanceConfig, while VLAN configurations for application interfaces
are applied separately via the AppInstanceConfig.

VIFs and NI ports that are not designated as VLAN access ports are configured by EVE
as trunk ports, allowing all VLANs with at least one access port.

### Local Network Instance IP Routing

Local Network Instance with multiple ports will have link-local and connected routes
from all the ports present in its routing table. Additionally, user may configure
[static IP routes](#application-ip-routing) which will be added into the routing table.
A static route may reference a particular gateway IP as the next hop, or a logical label
of a port to use as the output device, or use a shared label to match a subset of NI
ports if there are multiple possible paths to reach the routed destination network.

#### Multi-Path IP Routing

For every multi-path route with shared port label, EVE will perform periodic probing
of all matched network ports to determine the connectivity status and select the best
port to use for the route. Note that every multi-path route will have at most one output
port selected and configured at any time - load-balancing is currently not supported.

The probing method can be customized by the user as part of the route configuration.
If enabled, EVE will check the reachability of the port's next hop (the gateway IP)
every 15 seconds using ICMP ping. The upside of using this probe is fairly quick
fail-over when the currently used port for a given multi-path route looses connectivity.
The downside is that it may generate quite a lot of traffic over time. User may limit
the use of this probe to only ports with low cost or disable this probe altogether.
Additionally, every 2.5 minutes, EVE will run user-defined probe if configured.
This can be either an ICMP ping towards a given IP or hostname, or a TCP handshake
against the given IP/hostname and port.

A connectivity probe must consecutively success/fail few times in a row to determine
the connectivity as being up/down. EVE will then consider changing the currently used
port for a given route. The requirement for multiple consecutive test passes/failures
prevents from port flapping, i.e. re-routing too often. This is important, because
re-routing may break already established connections between apps and external endpoints.
This is due to a change in the IP used for the NAT.

Additionally to connectivity status, there are some other metrics that can affect
the port selection decision. For example, user may enable lower-cost-preference
for a given multi-path route. In that case, with multiple connected ports, EVE
will select the lowest-cost port. Similarly, route that uses multiple wwan ports,
can be configured to give preferential selection to cellular modem with better
network signal strength.

#### Network Instance Default IP Route

A typical use case for multi-path routing is the default route. Local NI with multiple
ports that have gateway IP defined cannot install default route for each of them
into the NI routing table. Load-balancing is not supported and using different metrics
(default behaviour in Linux with multiple default routes) would result in only
one of these routes being used. It is better to use multi-path routing with the probing
and fail-over capability for the default route.
For example, user may add default route and use a shared label that matches only those
ports that have Internet access.
When user-defined default route is not configured but NI has multiple ports assigned,
EVE will automatically create multi-path default route with next-hop probing enabled
(for ports with zero cost).
If the NI uses only uplink ports (i.e. mgmt ports), then additionally to next-hop
probing, TCP handshake against the controller URL and the port 443 will be used in
the place of the "user-defined probe".

### Application IP Routing

Most of the edge deployments will deploy applications that will have connectivity to both
WAN (Internet) and LAN (e.g. shop floor, machine floor).
There may be a single WAN port and multiple LAN ports.
User has the option to either create a single local network instance with all those ports
assigned and use the [IP routing capabilities of the network instance](#local-network-instance-ip-routing),
or create a separate instance for every port and use DHCP-based propagation of IP routes
into applications. The latter option, described below, is more difficult to configure
but gives the application full control over IP routing.

EVE uses DHCP (option 121) to propagate:

* *connected routes* to applications (routes for external networks that NI ports
  are connected to), and
* user-configured *static IP routes* to applications

Picture below portrays an example of an application with two interfaces, connected via
separate network instances to two different network ports. Blue color is used to highlight
the connected routes, which, when enabled, EVE will automatically propagate into the application.

For external networks one or more routing hops away (i.e. not directly connected to the device),
user is able to configure static IP routes and let EVE propagate them to the application
also using DHCP. Static routes are part of the network instance configuration. User configures
destination IP subnets which the network instance will become the gateway for (from the app
perspective). In the example below, the propagated static route is highlighted with the green
color:

![ni-ip-routing](./images/eve-ip-routing.png)

Another common case for route propagation is using one application as a network gateway
for other applications running on the same device. The gateway application may provide some
network function(s), such as firewall, IDS, network monitoring, etc. Such application will
connect on one side with the external network(s) using directly attached network adapter(s)
or via switch network instance(s), and the other side will make use of an air-gap local
network instance to connect with other applications running on the device. Propagated static
IP routes are necessary to make the application traffic flow through the gateway app.
In theory, multiple network functions can be chained together in this way using several
air-gap network instances with static IP routes.

In the example below, "Application 1" uses "Application 2" as a gateway for only one subnet,
while "Application 3" uses the application gateway for all the traffic. Green color highlights
static IP routes propagated to applications:

![ni-ip-routing-gw-app](./images/eve-ip-routing-app-gw.png)

#### Application Default IP Route

Network instance default route (with the NI bridge IP as the gateway) is automatically
propagated by DHCP to connected applications. The exceptions are:

* network instance is air-gapped (without port)
* all ports are app-shared and without default route

In both cases, it is possible to enforce default route propagation by configuring
a static default route for the network instance.

### Network Instance MTU

The user can adjust the Maximum Transmission Unit (MTU) size of the network instance
bridge and all application interfaces connected to it.
MTU determines the largest IP packet that the network instance is allowed to carry.
A smaller MTU value is often used to avoid packet fragmentation when some form of packet
encapsulation is being applied, while a larger MTU reduces the overhead associated with
packet headers, improves network efficiency, and increases throughput by allowing more
data to be transmitted in each packet (known as a jumbo frame).

EVE uses the L3 MTU, meaning the value does not include the L2 header size (e.g., Ethernet
header or VLAN tag size). The value is a 16-bit unsigned integer, representing the MTU size
in bytes. The minimum accepted value for the MTU is 1280, which is the minimum link MTU
needed to carry an IPv6 packet (see RFC 8200, "IPv6 minimum link MTU"). If the MTU for
a network instance is not defined (zero value), EVE will set the default MTU size of 1500
bytes.

On the host side, MTU is set to bridge and app VIFs by EVE. On the guest (application)
side, the responsibility to set the MTU lies either with EVE or with the user/app,
depending on the network instance type (local or switch), app type (VM or container)
and the type of interfaces used (virtio or something else).

#### Container App VIF MTU

For container applications running inside an EVE-created shim-VM, EVE initializes the MTU
of interfaces during the shim-VM boot. MTUs of all interfaces are passed to the VM via kernel
boot arguments (/proc/cmdline). The init script parses out these values and applies them
to application interfaces (excluding direct assignments).

Furthermore, interfaces connected to local network instances will have their MTUs
automatically updated using DHCP if there is a change in the MTU configuration. To update
the MTU of interfaces connected to switch network instances, user may run an external
DHCP server in the network and publish MTU changes via DHCP option 26 (the DHCP client
run by EVE inside shim-VM will pick them up and apply them).

#### VM App VIF MTU

In the case of VM applications, it is mostly the responsibility of the app/user to set
and keep the MTUs up-to-date. When device provides HW-assisted virtualization capabilities,
EVE (with kvm or kubevirt hypervisor) connects VM with network instances using para-virtualized
virtio interfaces, which allow to propagate MTU value from the host to the guest.
If the virtio driver used by the app supports the MTU propagation, the initial MTU values
will be set using virtio (regardless of the network instance type).

To determine if virtio driver used by an app supports MTU propagation, user must check
if `VIRTIO_NET_F_MTU` feature flag is reported as `1`.
Given that:

```c
#define VIRTIO_NET_F_MTU 3
```

Check the feature flag with (replace `enp1s0` with your interface name):

```sh
# the position argument of "cat" starts with 1, hence we have to do +1
cat /sys/class/net/enp1s0/device/features | cut -c 4
1 # if not supported, prints 0 instead
```

Please note that with the Xen hypervisor, the Xen's VIF driver does not support MTU
propagation from host to guest.

To support MTU change in run-time for interfaces connected to local network instances,
VM app can run a DHCP client and receive the latest MTU via DHCP option 26.
For switch network instances, the user can run his own external DHCP server in the network
with the MTU option configured.

With Kubevirt, MTU change after VMI is deployed is not possible. This is because the bridge
and the (virtio) TAP created by Kubevirt to connect pod interface (VETH) with the VMI interface
are fully managed by Kubevirt, which lacks the ability to detect and apply MTU changes.
This means that even if the app updates MTU on its side (using e.g. DHCP), the path MTU may
differ because the connection between the VMI and the underlying Pod will continue using
the old MTU value.

#### Network Instance MTU vs. Network Adapter MTU

Please note that application traffic leaving or entering the device via a network
adapter associated with the network instance is additionally limited by MTU values
of NI ports, configured within their `NetworkConfig` objects
(see [DEVICE-CONNECTIVITY.md](DEVICE-CONNECTIVITY.md), section "Network Adapter MTU").
If the configured network instance MTU is higher than MTU of any of the NI ports,
EVE will flag the network instance with an error and use the lowest MTU among
all the NI ports for the network instance instead. This is to prevent apps from sending
packets exceeding the path MTU. Packets entering NI via port with a higher MTU and with
size exceeding the NI MTU will get fragmented inside EVE (if allowed by IP header).
By default (if MTU is not configured by the user, i.e. 'mtu' is zero), EVE uses 1500
as MTU for air-gapped network instances and the lowest MTU among NI ports for NIs with
external connectivity.

### Flow Logging

If enabled for a given NI, EVE uses [Linux connection tracking](https://conntrack-tools.netfilter.org/manual.html)
to periodically (every 2 minutes) record all application TCP and UDP flows. A flow record
encapsulates application UUID, VIF name, open/close timestamps, src/dst IP/port/proto 5-tuple,
packet and byte counters.

Additionally, EVE captures DNS packets to make a recording of every DNS request from application.
This includes the request time, hostname that was being resolved and the returned IP address(es).

A batch of new flow records is published to the controller (POST `/api/v1/edgeDevice/flowlog`)
inside `FlowMessage`.

If flow logging is not needed, it is recommended to disable this feature as it can
potentially generate a large amount of data, which is then uploaded to the controller.
Depending on the implementation, it may also introduce additional packet processing overhead.
