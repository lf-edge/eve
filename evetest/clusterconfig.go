// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	cryptorand "crypto/rand"
	"encoding/base64"
	"net"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// ClusterNode identifies one node participating in the cluster.
// ClusterIP is the IP address (with prefix) assigned to this node on
// the cluster interface. ClusterInterface is the logical label of the
// physical port used for intra-cluster communication on this node.
// Exactly one node should have BootstrapNode set to true — its ClusterIP
// is used as the join server IP for all nodes.
type ClusterNode struct {
	DevName          string
	ClusterIP        *net.IPNet
	ClusterInterface string
	BootstrapNode    bool
}

// EdgeClusterConfig manages device configurations for a cluster of edge nodes.
// Methods that create UUID-identified objects (networks, network instances,
// applications, etc.) generate the UUID once and apply the same object to every
// node. Encrypted data (e.g. cluster join token, datastore credentials) is
// encrypted individually per device because each device has its own encryption
// key. For per-device customization, use GetDeviceConfig.
type EdgeClusterConfig struct {
	th        *TestHarness
	configs   map[string]*EdgeDeviceConfig // keyed by device name
	nodes     []ClusterNode                // preserves ordering
	ClusterID uuid.UUID
	Token     string // plaintext join token
}

// NewEdgeClusterConfig constructs an EdgeClusterConfig.
// It creates an EdgeDeviceConfig for each node, generates a shared cluster UUID
// and join token, and sets the cluster configuration on every device.
// The join token is encrypted individually per device.
func NewEdgeClusterConfig(
	clusterType eveconfig.ClusterType, nodes ...ClusterNode) *EdgeClusterConfig {
	th := getTestHarness()
	if len(nodes) == 0 {
		th.t.Fatalf("Edge Cluster requires at least one node")
	}

	// Find the bootstrap node to derive the join server IP.
	var joinServerIP string
	bootstrapCount := 0
	for _, node := range nodes {
		if node.BootstrapNode {
			bootstrapCount++
			if node.ClusterIP != nil {
				joinServerIP = node.ClusterIP.IP.String()
			}
		}
	}
	if bootstrapCount != 1 {
		th.t.Fatalf("Edge Cluster requires exactly one node marked "+
			"as BootstrapNode (found %d)", bootstrapCount)
	}

	cc := &EdgeClusterConfig{
		th:      th,
		configs: make(map[string]*EdgeDeviceConfig, len(nodes)),
		nodes:   nodes,
	}

	// Create per-device configs.
	for _, node := range nodes {
		cc.configs[node.DevName] = NewEdgeDeviceConfig(node.DevName)
	}

	// Generate a shared cluster UUID and join token.
	var err error
	cc.ClusterID = th.newUUID("edge cluster")
	tokenBytes := make([]byte, 20)
	if _, err = cryptorand.Read(tokenBytes); err != nil {
		th.t.Fatalf("Failed to generate cluster token: %v", err)
	}
	cc.Token = base64.StdEncoding.EncodeToString(tokenBytes)

	// Apply cluster config to each device with its own ClusterIP
	// and individually encrypted token.
	for _, node := range nodes {
		dc := cc.configs[node.DevName]
		devName := dc.GetDeviceName()

		if !th.isDeviceOnboarded(devName) {
			th.t.Fatalf("Device %q must be onboarded to encrypt cluster token", devName)
		}
		cipherData, err := th.encryptCipherData(devName,
			&evecommon.EncryptionBlock{
				ClusterToken: cc.Token,
			})
		if err != nil {
			th.t.Fatalf("Failed to encrypt cluster token for device %q: %v",
				devName, err)
		}

		dc.Cluster = &eveconfig.EdgeNodeCluster{
			ClusterId:             cc.ClusterID.String(),
			ClusterInterface:      node.ClusterInterface,
			ClusterType:           clusterType,
			JoinServerIp:          joinServerIP,
			EncryptedClusterToken: cipherData,
		}
		if node.ClusterIP != nil {
			dc.Cluster.ClusterIpPrefix = node.ClusterIP.String()
		}
	}

	return cc
}

// GetDeviceConfig returns the EdgeDeviceConfig for a specific device,
// allowing per-device customization.
func (cc *EdgeClusterConfig) GetDeviceConfig(devName string) *EdgeDeviceConfig {
	dc, ok := cc.configs[devName]
	if !ok {
		cc.th.t.Fatalf("Unknown cluster device %q", devName)
	}
	return dc
}

// forEachDevice calls fn on every device config in node order.
func (cc *EdgeClusterConfig) forEachDevice(fn func(dc *EdgeDeviceConfig)) {
	for _, node := range cc.nodes {
		fn(cc.configs[node.DevName])
	}
}

// SetConfigProperties sets configuration properties on all devices.
func (cc *EdgeClusterConfig) SetConfigProperties(configProps *pillartypes.ConfigItemValueMap) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.SetConfigProperties(configProps)
	})
}

// AddNetwork adds a network configuration to all devices.
// The same UUID is used across all devices.
func (cc *EdgeClusterConfig) AddNetwork(netConfig NetworkConfig) uuid.UUID {
	var networkUUID uuid.UUID
	for i, node := range cc.nodes {
		dc := cc.configs[node.DevName]
		if i == 0 {
			networkUUID = dc.AddNetwork(netConfig)
		} else {
			dc.addNetworkWithUUID(netConfig, networkUUID)
		}
	}
	return networkUUID
}

// UpdateNetwork updates an existing network on all devices.
func (cc *EdgeClusterConfig) UpdateNetwork(networkUUID uuid.UUID, newConfig NetworkConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateNetwork(networkUUID, newConfig)
	})
}

// DeleteNetwork removes a network from all devices.
func (cc *EdgeClusterConfig) DeleteNetwork(networkUUID uuid.UUID) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteNetwork(networkUUID)
	})
}

// AddNetworkAdapter adds a network adapter to all devices.
func (cc *EdgeClusterConfig) AddNetworkAdapter(config NetworkAdapterConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.AddNetworkAdapter(config)
	})
}

// UpdateNetworkAdapter updates a network adapter on all devices.
func (cc *EdgeClusterConfig) UpdateNetworkAdapter(config NetworkAdapterConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateNetworkAdapter(config)
	})
}

// DeleteNetworkAdapter removes a network adapter from all devices.
func (cc *EdgeClusterConfig) DeleteNetworkAdapter(logicalLabel string) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteNetworkAdapter(logicalLabel)
	})
}

// AddVLANSubinterface adds a VLAN sub-interface to all devices.
func (cc *EdgeClusterConfig) AddVLANSubinterface(config VLANSubinterfaceConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.AddVLANSubinterface(config)
	})
}

// UpdateVLANSubinterface updates a VLAN sub-interface on all devices.
func (cc *EdgeClusterConfig) UpdateVLANSubinterface(config VLANSubinterfaceConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateVLANSubinterface(config)
	})
}

// DeleteVLANSubinterface removes a VLAN sub-interface from all devices.
func (cc *EdgeClusterConfig) DeleteVLANSubinterface(logicalLabel string) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteVLANSubinterface(logicalLabel)
	})
}

// AddNetworkInstance adds a network instance to all devices.
// The same UUID is used across all devices.
func (cc *EdgeClusterConfig) AddNetworkInstance(config NetworkInstanceConfig) uuid.UUID {
	var niUUID uuid.UUID
	for i, node := range cc.nodes {
		dc := cc.configs[node.DevName]
		if i == 0 {
			niUUID = dc.AddNetworkInstance(config)
		} else {
			dc.addNetworkInstanceWithUUID(config, niUUID)
		}
	}
	return niUUID
}

// UpdateNetworkInstance updates a network instance on all devices.
func (cc *EdgeClusterConfig) UpdateNetworkInstance(
	niUUID uuid.UUID, newConfig NetworkInstanceConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateNetworkInstance(niUUID, newConfig)
	})
}

// DeleteNetworkInstance removes a network instance from all devices.
func (cc *EdgeClusterConfig) DeleteNetworkInstance(niUUID uuid.UUID) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteNetworkInstance(niUUID)
	})
}

// ClusterApplicationInstanceConfig wraps ApplicationInstanceConfig with
// cluster-specific fields required when deploying an application across
// a cluster of edge nodes.
type ClusterApplicationInstanceConfig struct {
	ApplicationInstanceConfig

	// DesignatedNodeName is the device name of the cluster node where
	// the application should be placed. This field is mandatory.
	DesignatedNodeName string

	// Affinity determines how strictly the designated node preference
	// is enforced. The default zero value is AFFINITY_TYPE_PREFERRED.
	Affinity eveconfig.AffinityType
}

// resolveDesignatedNodeID maps DesignatedNodeName to the device UUID.
func (cc *EdgeClusterConfig) resolveDesignatedNodeID(devName string) string {
	if devName == "" {
		cc.th.t.Fatalf("ClusterApplicationInstanceConfig: " +
			"DesignatedNodeName is mandatory")
	}
	if _, ok := cc.configs[devName]; !ok {
		cc.th.t.Fatalf("ClusterApplicationInstanceConfig: "+
			"DesignatedNodeName %q is not a member of this cluster", devName)
	}
	cc.th.devicesM.Lock()
	defer cc.th.devicesM.Unlock()
	devState, found := cc.th.devices[devName]
	if !found || devState.ID == NilUUID {
		cc.th.t.Fatalf("ClusterApplicationInstanceConfig: "+
			"device %q is not onboarded (cannot resolve UUID)", devName)
	}
	return devState.ID.String()
}

// setVolumeDesignatedNodeID sets DesignatedNodeId on a Volume and its
// associated ContentTree within the device config.
func (dc *EdgeDeviceConfig) setVolumeDesignatedNodeID(
	volumeUUID string, designatedNodeID string) {
	for _, vol := range dc.Volumes {
		if vol.Uuid == volumeUUID {
			vol.DesignatedNodeId = designatedNodeID
			if vol.Origin != nil {
				for _, ct := range dc.ContentInfo {
					if ct.Uuid == vol.Origin.DownloadContentTreeID {
						ct.DesignatedNodeId = designatedNodeID
					}
				}
			}
			return
		}
	}
}

// AddApplication adds an application to all devices.
// The same UUIDs (app, volume, content tree, datastore) are used across all devices.
// DesignatedNodeName is resolved to the device UUID and set on the AppInstanceConfig,
// Volume and ContentTree, along with the Affinity field on the app.
func (cc *EdgeClusterConfig) AddApplication(
	config ClusterApplicationInstanceConfig) uuid.UUID {
	designatedNodeID := cc.resolveDesignatedNodeID(config.DesignatedNodeName)
	appUUID := cc.th.newUUID("application")
	volumeUUID := cc.th.newUUID("application volume")
	contentTreeUUID := cc.th.newUUID("application image content tree")
	datastoreUUID := cc.th.newUUID("application image datastore")
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.addApplicationWithUUIDs(config.ApplicationInstanceConfig,
			appUUID, volumeUUID, contentTreeUUID, datastoreUUID)
		dc.Apps[len(dc.Apps)-1].DesignatedNodeId = designatedNodeID
		dc.Apps[len(dc.Apps)-1].Affinity = config.Affinity
		dc.setVolumeDesignatedNodeID(volumeUUID.String(), designatedNodeID)
	})
	return appUUID
}

// UpdateApplication updates an application on all devices.
// DesignatedNodeName is resolved to the device UUID and updated on
// the AppInstanceConfig, Volume and ContentTree, along with the Affinity field.
func (cc *EdgeClusterConfig) UpdateApplication(
	appUUID uuid.UUID, newConfig ClusterApplicationInstanceConfig) {
	designatedNodeID := cc.resolveDesignatedNodeID(newConfig.DesignatedNodeName)
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateApplication(appUUID, newConfig.ApplicationInstanceConfig)
		appUUIDStr := appUUID.String()
		for _, app := range dc.Apps {
			if app.Uuidandversion.Uuid == appUUIDStr {
				app.DesignatedNodeId = designatedNodeID
				app.Affinity = newConfig.Affinity
				for _, volRef := range app.VolumeRefList {
					dc.setVolumeDesignatedNodeID(volRef.Uuid, designatedNodeID)
				}
				break
			}
		}
	})
}

// DeleteApplication removes an application from all devices.
func (cc *EdgeClusterConfig) DeleteApplication(appUUID uuid.UUID) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteApplication(appUUID)
	})
}

// SetLPS sets the Local Profile Server configuration on all devices.
func (cc *EdgeClusterConfig) SetLPS(config LPSConfig) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.SetLPS(config)
	})
}

// AddSCEPProfile adds a SCEP profile to all devices.
// Encryption is performed individually per device.
func (cc *EdgeClusterConfig) AddSCEPProfile(profile SCEPProfile) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.AddSCEPProfile(profile)
	})
}

// UpdateSCEPProfile updates a SCEP profile on all devices.
func (cc *EdgeClusterConfig) UpdateSCEPProfile(profile SCEPProfile) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.UpdateSCEPProfile(profile)
	})
}

// DeleteSCEPProfile removes a SCEP profile from all devices.
func (cc *EdgeClusterConfig) DeleteSCEPProfile(profileName string) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		dc.DeleteSCEPProfile(profileName)
	})
}
