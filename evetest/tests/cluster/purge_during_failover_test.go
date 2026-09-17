// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package cluster_test

import (
	"fmt"
	"strconv"
	"testing"
	"time"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/evetest"
	"github.com/lf-edge/eve/evetest/netmodels"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// Timeouts for this test, named for it so the package can hold more than one
// set. Eventually returns as soon as its condition holds, so a generous budget
// costs nothing when the system behaves and only delays a genuine failure;
// each is set from an observed duration with headroom, never tuned to
// just-barely-pass.
const (
	// failoverClusterFormationTimeout bounds a three-node cluster forming, which is
	// slower than one node joining itself.
	failoverClusterFormationTimeout = 30 * time.Minute

	// failoverAppReadyTimeout bounds WaitUntilAppIsRunning. Excludes image download,
	// which the framework accounts for separately.
	failoverAppReadyTimeout = 10 * time.Minute

	// failoverRescheduleTimeout bounds KubeVirt rescheduling a replica after
	// its node is powered off. Dominated by the node-not-ready detection, not
	// by the pod.
	failoverRescheduleTimeout = 10 * time.Minute

	// failoverPurgeCompleteTimeout bounds PurgeApplication with
	// waitUntilPurged set.
	failoverPurgeCompleteTimeout = 5 * time.Minute

	// failoverEndStateTimeout bounds the assertion about the new generation.
	// Observed to settle within about a minute of the app coming back.
	failoverEndStateTimeout = 5 * time.Minute

	// failoverPollInterval is how often the end-state assertion re-checks.
	failoverPollInterval = 5 * time.Second

	// failoverVMIRSListTimeout bounds one kubectl invocation run over SSH.
	failoverVMIRSListTimeout = 20 * time.Second
)

const (
	// failoverThresholdKey configures how long an app's designated node has
	// to have been unhealthy before another cluster node may act on that app
	// in its place. Referenced by its literal string: pillar names it in a Go
	// constant only where that takeover is implemented, which this test does
	// not require to be present.
	failoverThresholdKey = types.GlobalSettingKey("cluster.dnid.backupnode.threshold")

	// failoverThresholdPin is what this test pins that setting to: six times
	// the longest it can hold the node down (failoverRescheduleTimeout plus
	// failoverPurgeCompleteTimeout plus failoverEndStateTimeout), and inside
	// the range the setting accepts.
	failoverThresholdPin = 2 * time.Hour
)

// failoverDeviceRequirements is clusterDeviceRequirements with the device
// always re-created from scratch. What this test asserts is precisely which
// generations of a workload exist, so a warm device carrying a previous test's
// purge counters would make a false pass indistinguishable from a true one.
func failoverDeviceRequirements(devName string, withTPM bool,
	filesystem evetest.Filesystem) evetest.RequireEdgeDevice {
	req := clusterDeviceRequirements(devName, withTPM, filesystem, false)
	req.DeviceReusePolicy = evetest.CreateFromScratchWithLiveImage
	return req
}

// vmShimApplication returns the app fixture: the standard evetest-ubuntu-ctr
// container run with VirtualizationMode=HVM. HVM, rather than the
// container-native NOHYPER default, is what makes domainmgr's kube path create
// a VMIRS (hypervisor/kubevirt.go CreateReplicaVMIConfig) instead of a plain
// pod, so this "shim VM" is the cheapest fixture that exercises the VMIRS
// lifecycle a purge has to drive.
//
// The forwarded SSH port is not used here - this test makes no guest-level
// assertion. It is part of the fixture so that this app is the same one
// tests/apps runs its purge tests against, and a difference in purge behavior
// cannot be put down to a difference in the app.
func vmShimApplication(
	displayName string, niUUID uuid.UUID) evetest.ApplicationInstanceConfig {
	return evetest.ApplicationInstanceConfig{
		DisplayName: displayName,
		Activate:    true,
		Image: evetest.DockerContainer{
			ImageName: "lfedge/evetest-ubuntu-ctr",
			Tag:       "1.0",
		},
		VirtualizationMode: eveconfig.VmMode_HVM,
		CPUs:               1,
		MemoryBytes:        500 * evetest.MiB,
		NetworkAdapters: []evetest.AppNetworkAdapter{
			evetest.VirtualNetworkAdapter{
				LogicalLabel:        "vif0",
				NetworkInstanceUUID: niUUID,
				PortFwdRules: []evetest.PortFwdRule{
					{
						Protocol:     evetest.NetworkProtocolTCP,
						EdgeNodePort: 2222,
						AppPort:      22,
					},
				},
				ACLAllowRules: []evetest.ACLAllowRule{
					{
						Protocol:     evetest.NetworkProtocolAny,
						RemoteSubnet: evetest.IPSubnet("0.0.0.0/0"),
					},
				},
			},
		},
	}
}

// appPurgeCounter reads the persisted purge counter zedmanager keeps for
// appUUID (pkg/pillar/types.UuidToNum, NumType "purgeCmdCounter"). It is not
// republished anywhere in the EVE API, so it is read from the persisted pubsub
// state.
//
// found is false only if the record could not be read: zedmanager allocates it
// when it first handles the app's config, so it exists from well before the
// app's first purge, holding 0.
func appPurgeCounter(
	dev *evetest.EdgeDevice, appUUID uuid.UUID) (counter uint32, found bool) {
	var rec types.UuidToNum
	if err := evetest.ReadPublication(
		dev, "zedmanager", true, appUUID.String(), &rec); err != nil {
		// Absent before the app's first purge, which is expected; a transient
		// read failure lands here too and the caller's retry absorbs it.
		return 0, false
	}
	return uint32(rec.Number), true
}

// assertExactlyOneVMIRSAtGeneration is this test's end-state detector: after a
// purge to newCounter there must be exactly one VMIRS for the app, and it must
// be named for the NEW generation - not the old one (a stalled purge leaves the
// old generation's VMIRS alone) and not both (the old generation's VMIRS
// surviving alongside a newly created one).
func assertExactlyOneVMIRSAtGeneration(
	g Gomega, dev *evetest.EdgeDevice, appUUID uuid.UUID, appDisplayName string,
	newCounter uint32) {
	// base.GetAppKubeNameWithPurge would be the exact match for this (name + "-"
	// + purge counter), but it is newer than the pillar module version currently
	// pinned by evetest's go.mod, so the suffix is appended here instead - see
	// base.GetAppKubeNameWithPurge's own implementation for why this is exactly
	// equivalent.
	wantName := base.GetAppKubeName(appDisplayName, appUUID) + "-" +
		strconv.FormatUint(uint64(newCounter), 10)
	names, err := dev.ListAppVMIRS(appUUID, failoverVMIRSListTimeout)
	g.Expect(err).ToNot(HaveOccurred(),
		"could not list VMIRS objects; k3s may still be starting")
	g.Expect(names).To(HaveLen(1),
		"expected exactly one VMIRS for the app, found %v", names)
	if len(names) == 1 {
		g.Expect(names[0]).To(Equal(wantName),
			"the surviving VMIRS must be the NEW generation %q, not a stale one", wantName)
	}
}

// TestVMAppPurgeDuringFailover exercises a purge issued after the app's
// designated node has failed over: the app's designated node is powered
// off, KubeVirt reschedules the replica onto a different node, and a purge
// is then issued while the designated node is still down. The purge must
// not wait on the dead node: gating the teardown on the app's designated
// node, or on where a replica currently happens to be scheduled, would
// deadlock exactly this case, because neither signal is both durable and
// liveness-aware on its own.
//
// Network model
// -------------
//   - netmodels.SeparateClusterPort -- six ports (two per device): eth0
//     ports share a management+app SDN bridge with DHCP and controller
//     reachability; eth1 ports share a separate cluster-only bridge used
//     for inter-node K3s traffic.
//
// Device configuration
// --------------------
//   - Three failoverDeviceRequirements devices - clusterDeviceRequirements
//     always re-created from scratch - following TestThreeNodesCluster's
//     topology.
//   - ClusterConfig (REPLICATED_STORAGE) with three ClusterNode entries on
//     10.244.244.0/24; node 1 is the bootstrap node.
//   - One Local NI "local-ni" (10.11.14.0/24) and one shim-VM app
//     (vmShimApplication) with DesignatedNodeName=devName[0] (node 1) and
//     Affinity=PREFERRED.
//   - failoverThresholdKey pinned past the test's own duration, so no peer
//     ever becomes eligible to act for the powered-off designated node. The
//     purge asserted below is the one that needs no such stand-in.
//
// Test parameters
// ---------------
//   - TPM via evetest.TPMParameter().
//   - FILESYSTEM (ext4|zfs, defaults to ext4) via evetest.FilesystemParameter().
//
// Phases
// ------
//  1. setup-done -> nodes-are-ready: bring up the three-node cluster.
//  2. app-is-deployed: deploy the app; assert it is in fact running on its
//     preferred (DNID) node, node 1, while node 1 is healthy.
//  3. dnid-node-powered-off: EdgeDevice.PowerOff() on node 1.
//  4. failed-over: EdgeCluster.FindDeviceHostingApp with node 1 excluded waits
//     for KubeVirt to reschedule the replica onto node 2 or node 3. The
//     exclusion matters: without it the powered-off node's own stale cluster
//     info still names it as the host and would be returned immediately.
//  5. purge-complete: EdgeCluster.PurgeApplication, waiting until purged -
//     this bumps the purge counter on every device (including the
//     powered-off node 1 - EdgeDevice.ApplyConfig's push does not require
//     device reachability) but waits only on the node actually hosting the
//     app; there is no exclusive gate on the delete itself.
//  6. purge-end-state-asserted: exactly one VMIRS, named for the NEW
//     generation, observed from the node that now hosts the app. No volume or
//     guest-level assertion is made here (VolumeStatus is a per-node ephemeral
//     publication and its
//     clustered/replicated-storage semantics across a node failover have
//     not been established for this suite; the app's forwarded SSH port on
//     the new host has not been either).
//
// Node 1 is powered back on from a defer armed at step 3, so cluster teardown
// never has to reason about an already-off device -- including when an
// assertion above aborts the test body.
//
// Suite placement
// ---------------
//   - TestNodeClusterSuite, after the other three-node subtests: it powers a
//     node off and needs a cluster of its own, so it is the most expensive one
//     to set up.
func TestVMAppPurgeDuringFailover(test *testing.T) {
	evetestT := evetest.Init(test)
	t := NewGomegaWithT(evetestT)
	defer evetest.Close()

	evetest.DefineTestParameters(
		evetest.TPMParameter(),
		evetest.FilesystemParameter(),
	)
	withTPM := evetest.GetTPMParameterValue()
	filesystem := evetest.GetFilesystemParameterValue()

	var requiredDevices [3]evetest.Requirement
	var devName [3]string
	for i := 0; i < 3; i++ {
		devName[i] = fmt.Sprintf("edge-dev%d", i+1)
		requiredDevices[i] = failoverDeviceRequirements(devName[i], withTPM, filesystem)
	}
	requiredNetModel := evetest.RequireNetworkModel{
		NetworkModel: netmodels.SeparateClusterPort,
	}
	var requirements []evetest.Requirement
	requirements = append(requirements, requiredDevices[:]...)
	requirements = append(requirements, requiredNetModel)
	evetest.Setup(requirements...)
	evetest.Checkpoint("setup-done")

	var nodes [3]evetest.ClusterNode
	for i := 0; i < 3; i++ {
		clusterIP := evetest.IPAddressWithPrefix(fmt.Sprintf("10.244.244.%d/24", i+2))
		nodes[i] = evetest.ClusterNode{
			DevName:          devName[i],
			ClusterIP:        clusterIP,
			ClusterInterface: "ethernet1",
			BootstrapNode:    i == 0,
		}
	}
	clusterConfig := evetest.NewEdgeClusterConfig(
		eveconfig.ClusterType_CLUSTER_TYPE_REPLICATED_STORAGE,
		nodes[:]...,
	)

	// The default threshold is ten minutes, which is not margin enough to say
	// that the purge below ran without a peer standing in for the downed node:
	// the failover wait alone is allowed ten minutes, so a slow failover would
	// leave the purge running just as a peer became eligible. Pinning the
	// threshold past the whole test removes the overlap. A device that does
	// not implement the setting records a parse error for the item and applies
	// the rest of the config, and has no such takeover to begin with.
	cfgProps := types.NewConfigItemValueMap()
	cfgProps.SetGlobalValueInt(failoverThresholdKey,
		uint32(failoverThresholdPin.Seconds()))
	clusterConfig.SetConfigProperties(cfgProps)

	dhcpNet := clusterConfig.AddNetwork(
		evetest.DHCPNetworkConfig{
			NetworkType: evecommon.NetworkType_V4Only,
		})
	noIPNet := clusterConfig.AddNetwork(evetest.NoIPNetworkConfig{})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet0",
			PhysicalLabel: "eth0",
			InterfaceName: "eth0",
			NetworkUUID:   dhcpNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
		})
	clusterConfig.AddNetworkAdapter(
		evetest.NetworkAdapterConfig{
			LogicalLabel:  "ethernet1",
			PhysicalLabel: "eth1",
			InterfaceName: "eth1",
			NetworkUUID:   noIPNet,
			Usage:         evecommon.PhyIoMemberUsage_PhyIoUsageShared,
		})

	cluster := evetest.NewEdgeCluster("purge-failover-cluster")
	cluster.ApplyConfig(clusterConfig, true, true)
	evetest.Checkpoint("initial-config-applied")

	cluster.WaitUntilNodesAreReady(failoverClusterFormationTimeout)
	evetest.Checkpoint("nodes-are-ready")

	niUUID := clusterConfig.AddNetworkInstance(evetest.LocalNetworkInstanceConfig{
		DisplayName: "local-ni",
		Port:        "ethernet0",
		Subnet:      evetest.IPSubnet("10.11.14.0/24"),
		DHCPRange: types.IPRange{
			Start: evetest.IPAddress("10.11.14.2"),
			End:   evetest.IPAddress("10.11.14.254"),
		},
		Gateway:       evetest.IPAddress("10.11.14.1"),
		EnableFlowlog: true,
		MTU:           1500,
		ForwardLLDP:   false,
	})
	const appDisplayName = "failover-purge-app"
	appUUID := clusterConfig.AddApplication(evetest.ClusterApplicationInstanceConfig{
		ApplicationInstanceConfig: vmShimApplication(appDisplayName, niUUID),
		DesignatedNodeName:        devName[0],
		Affinity:                  eveconfig.AffinityType_AFFINITY_TYPE_PREFERRED,
	})
	cluster.ApplyConfig(clusterConfig, true, true)
	log := evetest.Logger()
	log.Infof("Submitted config with application UUID=%v, DNID node=%q", appUUID, devName[0])
	evetest.Checkpoint("app-config-is-submitted")

	cluster.WaitUntilAppIsRunning(appUUID, failoverAppReadyTimeout)
	evetest.Checkpoint("app-is-deployed")

	initialHost := cluster.FindDeviceHostingApp(appUUID, time.Minute)
	t.Expect(initialHost.Name()).To(Equal(devName[0]),
		"app should have been scheduled onto its preferred (DNID) node while it is healthy")

	dnidDevice := evetest.GetEdgeDevice(devName[0])
	baselineCounter, found := appPurgeCounter(dnidDevice, appUUID)
	t.Expect(found).To(BeTrue(),
		"zedmanager allocates the purge-counter record when it first handles the "+
			"app config, so it exists long before any purge; not finding it means "+
			"the read failed, and the baseline would silently be 0")
	t.Expect(baselineCounter).To(BeZero(),
		"the app has not been purged yet, so its counter must still be 0; "+
			"anything else means the baseline is not the one the assertions assume")

	// Whether the pin took effect is only visible in what each device reports
	// back for the key: a value means it holds the pin, an error means it does
	// not know the setting.
	for _, name := range devName {
		item := evetest.GetEdgeDevice(name).GetDeviceInfo().GetConfigItemStatus().
			GetConfigItems()[string(failoverThresholdKey)]
		log.Infof("Device %q reports %s=%q (error: %q)", name,
			failoverThresholdKey, item.GetValue(), item.GetError())
	}

	log.Infof("Powering off DNID node %q to force a failover", devName[0])
	dnidDevice.PowerOff()
	// Deferred rather than done at the end of the test: an assertion failure
	// below aborts the test body, and cluster teardown then has to reason about
	// a member that is still powered off.
	defer func() {
		log.Infof("Powering DNID node %q back on", devName[0])
		dnidDevice.PowerOn(true)
	}()
	evetest.Checkpoint("dnid-node-powered-off")

	failoverHost := cluster.FindDeviceHostingApp(
		appUUID, failoverRescheduleTimeout, devName[0])
	log.Infof("App failed over to device %q", failoverHost.Name())
	evetest.Checkpoint("failed-over")

	// BumpVolumeGeneration: the purge under test is the one that increments
	// the generation on the volume the cluster already replicates, not the
	// fresh-UUID path. devName[0] is powered off, so it is excluded from the
	// search for the node to wait on.
	cluster.PurgeApplication(appUUID, evetest.BumpVolumeGeneration, true,
		failoverPurgeCompleteTimeout, devName[0])
	evetest.Checkpoint("purge-complete")

	wantCounter := baselineCounter + 1
	t.Eventually(func(g Gomega) {
		assertExactlyOneVMIRSAtGeneration(g, failoverHost, appUUID, appDisplayName, wantCounter)
	}, failoverEndStateTimeout, failoverPollInterval).Should(Succeed())
	evetest.Checkpoint("purge-end-state-asserted")
}
