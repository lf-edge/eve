# Application Network Connectivity Management Agent in EVE (aka zedrouter)

## Overview

Zedrouter provisions the network connectivity for the application instances by provisioning the network instances and then attaching the application instances to the specified network instances.

## Key Input/Output

Zedrouter subscribes to AppNetworkConfig from zedmanager, and publishes AppNetworkStatus plus NetworkMetrics for the provisioning of the connectivity from the application side.

It subscribes to NetworkInstanceConfig from zedagent and publishes NetworkInstanceStatus and NetworkInstanceMetrics for the provisioning of the network instances.

In addition it publishes IPFlow and AppContainerMetrics.

## Network instances

Each network instance corresponds to one virtual switch which is implemented using a Linux bridge.
If the network instance is of type switch that is basically it.
For the other network instances (local, cloud, and mesh) there is also an instance of dnsmasq which is deployed for the network instance to provide DHCP and DNS service, including the ability to manage ip sets for DNS-name based firewall rules.

All network instances have firewall rules aka access control lists which are implemented using iptables in such a way that we also get flow log information.

Local network instances which have a specified external port are provisioned with iptables NAT rules for outbound connectivity plus any inbound connectivity specified in the firewall rules.

## Vifs

When an AppNetworkConfig specifies that an application instance should be attached to a particular network instance then zedrouter will provision a unique MAC address for that vif, provision dnsmasq with an IP address and a DNS hostname for the vif,  create the iptables rules based on the firewall rules including any ip sets, and add the vif to the bridge.
