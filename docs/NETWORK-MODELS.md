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

Currently, the only natively supported L3 network is a NAT-based _Local_ Network Instance.
The idea is that anything more advanced (VPN, network mesh, etc.) should be provided by an application.

##### Local Network Instance

A `Local` network is the simplest and the only natively supported L3 network. It may have:

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
