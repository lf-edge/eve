// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"compress/gzip"
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
// At most one node may have TieBreaker set to true.
type ClusterNode struct {
	DevName          string
	ClusterIP        *net.IPNet
	ClusterInterface string
	BootstrapNode    bool

	// TieBreaker marks this node as the cluster tie-breaker: the third
	// node of an HA cluster, which exists only to give etcd a quorum
	// vote. EVE keeps it cordoned, runs no workloads on it and places no
	// Longhorn replicas there, which also lowers the replica count of
	// the storage class used for new volumes.
	//
	// Leave it false on every node to configure no tie-breaker at all.
	TieBreaker bool
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

	// Cluster-wide settings every node's EdgeNodeCluster block is built from,
	// so AddNode can configure a later node identically.
	clusterType      eveconfig.ClusterType
	joinServerIP     string
	tieBreakerNodeID string
	nativeK8s        bool
	gzipManifest     []byte // gzipped registration manifest, empty if unset
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

	// Find the bootstrap node to derive the join server IP, and the
	// tie-breaker node (if any) to derive its UUID below.
	var joinServerIP, tieBreakerDevName string
	bootstrapCount := 0
	tieBreakerCount := 0
	for _, node := range nodes {
		if node.BootstrapNode {
			bootstrapCount++
			if node.ClusterIP != nil {
				joinServerIP = node.ClusterIP.IP.String()
			}
		}
		if node.TieBreaker {
			tieBreakerCount++
			tieBreakerDevName = node.DevName
		}
	}
	if bootstrapCount != 1 {
		th.t.Fatalf("Edge Cluster requires exactly one node marked "+
			"as BootstrapNode (found %d)", bootstrapCount)
	}
	if tieBreakerCount > 1 {
		th.t.Fatalf("Edge Cluster allows at most one node marked "+
			"as TieBreaker (found %d)", tieBreakerCount)
	}

	cc := &EdgeClusterConfig{
		th:           th,
		configs:      make(map[string]*EdgeDeviceConfig, len(nodes)),
		nodes:        nodes,
		clusterType:  clusterType,
		joinServerIP: joinServerIP,
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

	// Resolve the tie-breaker device name to the UUID that EVE knows it
	// by. Every node is told which node is the tie-breaker, because each
	// one compares the configured UUID against its own to decide whether
	// it must apply the tie-breaker role to itself.
	var tieBreakerNodeID string
	if tieBreakerDevName != "" {
		id, onboarded := th.deviceUUID(tieBreakerDevName)
		if !onboarded {
			th.t.Fatalf("Device %q must be onboarded to be the cluster "+
				"tie-breaker (cannot resolve UUID)", tieBreakerDevName)
		}
		tieBreakerNodeID = id.String()
	}
	cc.tieBreakerNodeID = tieBreakerNodeID

	// Apply cluster config to each device with its own ClusterIP
	// and individually encrypted token.
	for _, node := range nodes {
		cc.setNodeClusterConfig(node)
	}

	return cc
}

// setNodeClusterConfig (re)builds one node's EdgeNodeCluster block from the
// cluster-wide settings plus that node's own cluster IP.
//
// The cluster name is preserved: it belongs to the EdgeCluster handle, which
// stamps it on in ApplyConfig, so rebuilding a block after the first apply
// would otherwise rename the cluster for that node.
func (cc *EdgeClusterConfig) setNodeClusterConfig(node ClusterNode) {
	dc := cc.configs[node.DevName]
	clusterName := dc.Cluster.GetClusterName()
	dc.Cluster = &eveconfig.EdgeNodeCluster{
		ClusterName:                  clusterName,
		ClusterId:                    cc.ClusterID.String(),
		ClusterInterface:             node.ClusterInterface,
		ClusterType:                  cc.clusterType,
		JoinServerIp:                 cc.joinServerIP,
		EncryptedClusterToken:        cc.encryptClusterSecrets(node.DevName),
		TieBreakerNodeId:             cc.tieBreakerNodeID,
		EnableNativeK8SOrchestration: cc.nativeK8s,
	}
	if node.ClusterIP != nil {
		dc.Cluster.ClusterIpPrefix = node.ClusterIP.String()
	}
}

// encryptClusterSecrets encrypts the join token and, when set, the
// registration manifest for one device. Both ride in one EncryptionBlock
// because EVE reads them from one cipher block: zedagent's
// parseEdgeNodeClusterConfig points CipherGzipRegistrationManifestYaml at the
// block it parsed the token from. Each device has its own key.
func (cc *EdgeClusterConfig) encryptClusterSecrets(devName string) *evecommon.CipherBlock {
	if !cc.th.isDeviceOnboarded(devName) {
		cc.th.t.Fatalf("Device %q must be onboarded to encrypt cluster secrets", devName)
	}
	cipherData, err := cc.th.encryptCipherData(devName,
		&evecommon.EncryptionBlock{
			ClusterToken:                 cc.Token,
			GzipRegistrationManifestYaml: cc.gzipManifest,
		})
	if err != nil {
		cc.th.t.Fatalf("Failed to encrypt cluster secrets for device %q: %v",
			devName, err)
	}
	return cipherData
}

// SetNativeK8SOrchestration enables native Kubernetes orchestration of user
// workloads ("base mode"), the opt-in that replaced CLUSTER_TYPE_K3S_BASE: EVE
// then serves EVE-API-scheduled and natively-applied workloads side by side.
//
// The EVE API only accepts it on CLUSTER_TYPE_REPLICATED_STORAGE, so any other
// type fails here rather than being rejected by EVE. AddNode inherits it.
func (cc *EdgeClusterConfig) SetNativeK8SOrchestration(enabled bool) {
	if enabled && cc.clusterType != eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE {
		cc.th.t.Fatalf("Native Kubernetes orchestration requires cluster type %v, "+
			"but this cluster is %v",
			eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE, cc.clusterType)
	}
	cc.nativeK8s = enabled
	cc.forEachClusterBlock(func(cluster *eveconfig.EdgeNodeCluster) {
		cluster.EnableNativeK8SOrchestration = enabled
	})
}

// forEachClusterBlock calls fn on every node's EdgeNodeCluster block. A node
// whose block a test cleared (how a member is converted back to standalone) is
// skipped, not resurrected.
func (cc *EdgeClusterConfig) forEachClusterBlock(fn func(cluster *eveconfig.EdgeNodeCluster)) {
	cc.forEachDevice(func(dc *EdgeDeviceConfig) {
		if dc.Cluster != nil {
			fn(dc.Cluster)
		}
	})
}

// SetRegistrationManifest attaches a manifest for the cluster to apply to
// itself once up -- how a controller registers an EVE-K cluster.
//
// It shares the join token's cipher block, so this re-encrypts that block for
// every node. Only the bootstrap node acts on it: zedkube writes
// /persist/vault/manifests/registration.yaml, kube-init stages it into the k3s
// server-manifests dir, and k3s applies it as the "persist-registration" AddOn.
//
// Pass nil to remove it. AddNode inherits whatever is set at that point.
func (cc *EdgeClusterConfig) SetRegistrationManifest(manifestYAML []byte) {
	if len(manifestYAML) == 0 {
		cc.gzipManifest = nil
	} else {
		cc.gzipManifest = cc.gzipManifestYAML(manifestYAML)
	}
	// Re-encrypt the joint token+manifest block for every node.
	for _, node := range cc.nodes {
		cluster := cc.configs[node.DevName].Cluster
		if cluster == nil {
			continue
		}
		cluster.EncryptedClusterToken = cc.encryptClusterSecrets(node.DevName)
	}
}

// gzipManifestYAML compresses the manifest as EVE expects to receive it
// (kubeapi.RegistrationAdd inflates it with compress/gzip).
func (cc *EdgeClusterConfig) gzipManifestYAML(manifestYAML []byte) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(manifestYAML); err != nil {
		cc.th.t.Fatalf("Failed to compress the registration manifest: %v", err)
	}
	if err := gz.Close(); err != nil {
		cc.th.t.Fatalf("Failed to compress the registration manifest: %v", err)
	}
	return buf.Bytes()
}

// AddNode extends a built cluster configuration with one more node, which is
// how a test grows a running cluster. The device must already be onboarded;
// call EdgeCluster.ApplyConfig afterwards to push the result.
//
// The new node is cloned from the first node, so it shares its networks,
// adapters, network instances and applications under the same UUIDs -- which
// is what makes it a peer rather than a lookalike. Only the cluster IP and the
// per-device secrets are rebuilt. Two consequences:
//
//   - Only the first node is the template, so a GetDeviceConfig customization
//     made on another node is not carried over.
//   - The new node is never the bootstrap node, and never the tie-breaker:
//     that has to be named at construction, since every node is told which
//     node it is.
func (cc *EdgeClusterConfig) AddNode(node ClusterNode) {
	if _, exists := cc.configs[node.DevName]; exists {
		cc.th.t.Fatalf("Device %q is already part of the cluster configuration",
			node.DevName)
	}
	if node.BootstrapNode {
		cc.th.t.Fatalf("Device %q cannot join as a bootstrap node: the cluster "+
			"already has one", node.DevName)
	}
	if node.TieBreaker {
		cc.th.t.Fatalf("Device %q cannot join as the tie-breaker: the tie-breaker "+
			"must be designated when the cluster configuration is created, "+
			"because every node is told which node it is", node.DevName)
	}
	template := cc.configs[cc.nodes[0].DevName].Clone()
	template.DeviceName = node.DevName
	// Cipher contexts are per device, so the cloned list is the wrong one;
	// ApplyConfig republishes the harness-held list anyway.
	template.CipherContexts = nil
	cc.configs[node.DevName] = template
	cc.nodes = append(cc.nodes, node)
	cc.setNodeClusterConfig(node)
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
