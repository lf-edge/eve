# Network Models

What are the network models that EVE supports for Edge Container workloads, and how are they implemented?

The first half of this document describes _what_ those network models are and how they impact Edge Container (ECO) communications. The second half describes _how_ those models are implemented.

## Models

Fundamentally, each ECO _may_ need to communicate with services outside itself. Those can be one or more of:

* other ECOs on the same device
* a communications network to which the device, on which the ECO is running, is attached via some i/o port, e.g. a NIC
* one or more ECOs on one or more other devices
* a remote network accessible via a VPN

In principle, an Edge Container definition does not define any of its methodologies, networks or technologies. It simply defines what it should be able to connect to. The Controller then is responsible for translating those networking permissions to implementations passed on to EVE.

Put in other terms, the various complex methods of networking are the responsibility of the _Controller_ to define and expose to users. EVE itself, on the other hand, is responsible solely for providing basic networking building blocks that enable all of the necessary forms of communication, and which a Controller can meld together to provide the necessary networking services.

## Definitions

* `network`: a joining together of one or more endpoints on a device that will be able to communicate with each other via packets
* `endpoint`: a unique connection point to a network, includes ECOs and one or more communications media
* `Edge Container (ECO)`: a single running workload on a single device, which can be connected as an endpoint to 0, 1 or multiple networks simultaneously
* `port`: an endpoint, which can be backed by a physical device, e.g. a NIC or a serial port

## Responsibilities

From the perspective of EVE on a single device, which is its entire scope of responsibility, EVE needs to be informed of the following:

* that a network should exist on the device, and a representative name for it
* what the network type is: L2 or L3 (see below)
* the endpoints that are to be connected to that network (see below)

EVE receives these as part of its `EdgeDeviceConfig`, returned when querying the [/config API Controller Endpoint](../api/README.md#Configuration). EVE then should either create a network that matches the specifications and connect endpoints, or update one if it already exists.

### Network Type

EVE must be able to create two types of networks, `L2` or `L3`.

#### L2 Networks

L2 networks are straight bridged networks. They have the following characteristics:

* No IP-level services provided by EVE, e.g. DHCP or DNS
* All packets sent into the network must have their layer 2 frames preserved
* Any endpoints connected via off-device connections, such as ports, are simply bridged onto the network as is
* Only one network port may be connected to the network at any time, to avoid spanning tree issues

#### L3 networks

L3 networks are isolated local networks with their own IP space and services. They have the following characteristics:

* EVE provides basic IPAM services, including DHCP and DNS
* All packets sent into the network may have their layer 2 frames modified, if required by the network
* All networks connected off-device, such as via NICs, do not directly connect to the off-device network, but instead have some network "proxying" or "connectivity" service that connects; see details below.

The difference between the different L3 networks, and thus the higher-level types of networks offered by EVE, depend on the connectivity to the off-device networking world. There are
several types.

* Local: Either no off-device connectivity, or one port fronted via NAT.
* Cloud: Off-device connectivity via an IPSec VPN to a cloud provider's VPC.
* Mesh: Off-device connectivity via a LISP mesh to other devices.

As described above, all of these use L3, may modify L2 frames, and provide IPAM services.

##### Local

A `Local` network is the simplest L3 network. It may have:

* 1, 2 or any number of ECOs on the device connected.
* 0 or 1 ports off-device connected. If 0, then the ECOs can communicate with each other over this network, but nowhere else. If 1, then EVE places a NAT between the local network and the port, enabling the ECOs to communicate with whatever is on the other side of the port, with all communications NATted.

There is no connection directly to the off-device network; remote access is available solely through the NAT.

If an EVE device is instructed to connect ECOs via L3, it should do the following:

1. Set up an L3 network on the device using a Linux bridge
1. Connect all ECOs which have this `Local` network enabled to the bridge
1. If a port has been allocated to the network:
   * Set up NAT
   * Connect the designated port to the NAT
   * Connect the NAT to the bridge

##### Cloud

A `Cloud` network is an L3 network with a VPN connection. It may have:

* 1, 2 or any number of ECOs on the device connected.

In addition, it has an IPSec VPN connected to a remote endpoint, usually in a VPC in a cloud provider, although technically the VPN remote end could be anywhere. There is
just one port active, which serves the VPN, although it can have more ports dedicated to the VPN to serve as standby.

This enables the ECOs on the device to communicate with each other, identically to a `Local` network, and also over the VPN to the remote end.

There is no connection directly to the off-device network; remote access is available solely through the VPN.

If an EVE device is instructed to connect ECOs to a remote VPN endpoint, it should do the following:

1. Verify that there is at least one port allocated to the network over which the VPN can connect to the remote endpoint
1. Set up the VPN connection
1. Set up an L3 network on the device using a Linux bridge
1. Connect all ECOs which have this `Cloud` network enabled to the bridge, as well as the VPN connection

EVE must be capable of supporting the following VPN implementations:

* IPSec

Additional VPN implementations, such as wireguard, are under consideration; Pull Requests are welcome.

##### Mesh

A `Mesh` network is an L3 network wherein a mesh has been created with zero, one or more L3 networks on other EVE devices. The `Mesh` network creates the
impression of a single large L3 network encompassing all of the ECOs on all of the EVE devices that participate in the mesh.

It may have:

* 1, 2 or any number of ECOs on the device connected.
* 1, 2 or any number of ECOs on any number of other devices connected.

Unlike the `Local` network, which has a NAT connection off-device, and unlike the `Cloud` network, which has a VPN connection to a remote VPN endpoint, the `Mesh` network links all
of the ECOs which participate to communicate over L3.

There is no connection directly to the off-device network; remote access is available solely through the mesh network.
