// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Inputs to the harness, and suite-wide tunables.
//
// Rule for this file: if a helper takes no *evetest.EdgeDevice and reads nothing
// off a device, it belongs here. Everything here describes what to build before a
// test runs; nothing here observes a running system.

package apps_test

import (
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	uuid "github.com/satori/go.uuid"
)

// Timeouts for this suite, in one place so they can be reviewed together.
//
// Sizing principle: Eventually returns as soon as its condition holds, so a
// generous timeout costs nothing when the system behaves and only delays a
// genuine failure. Each of these is set from an observed duration with real
// headroom, never tuned to just-barely-pass. If one of them starts expiring,
// the answer is to find out what changed - not to raise the number.
const (
	// assertPollInterval is how often the end-state assertions re-check.
	assertPollInterval = 5 * time.Second

	// appReadyTimeout bounds WaitUntilAppIsRunning. Excludes image download,
	// which the framework accounts for separately.
	appReadyTimeout = 10 * time.Minute

	// purgeCompleteTimeout bounds PurgeApplication(waitUntilPurged=true).
	purgeCompleteTimeout = 5 * time.Minute

	// baselineTimeout bounds reading the pre-purge state. Everything it reads is
	// already published by the time the app reports RUNNING, so this only
	// absorbs publication lag.
	baselineTimeout = 2 * time.Minute

	// purgeEndStateTimeout bounds the assertions about the NEW generation:
	// counter advanced, purge phase finished, app running, one volume, one
	// workload. Observed to settle within about a minute of the app coming back.
	purgeEndStateTimeout = 5 * time.Minute

	// storageReclaimTimeout bounds removal of the OLD generation's disk, which
	// is a separate concern on a separate clock: the purge is complete once the
	// app runs on the new generation, and volumemgr reclaims the previous
	// artifact afterwards - observed at roughly five minutes, far short of the
	// one-hour VdiskGCTime but far longer than the purge itself.
	storageReclaimTimeout = 15 * time.Minute

	// storageReclaimPollInterval is deliberately coarse: each poll shells out to
	// the device, and nothing is expected to change for minutes.
	storageReclaimPollInterval = 15 * time.Second

	// clusterReadyTimeout bounds a single eve-k node becoming Ready. k3s and
	// Longhorn take minutes to come up, and an app deployed before that sits in
	// INITIAL - burning the app-ready budget on something that is not the app.
	// Measured at about six minutes on a 4-vCPU node; every other test in this
	// package allows twenty.
	clusterReadyTimeout = 20 * time.Minute

	// clusterFormationTimeout bounds a multi-node cluster forming, which is
	// slower than one node joining itself.
	clusterFormationTimeout = 30 * time.Minute

	// failoverTimeout bounds KubeVirt rescheduling a replica after its node is
	// powered off. Dominated by the node-not-ready detection, not by the pod.
	failoverTimeout = 10 * time.Minute
)

// purgeDeviceRequirements returns the RequireEdgeDevice used by every test in
// this suite: a node on the requested hypervisor, always created fresh so a
// previous test's purge counters or workload generations can never leak into
// this one - the invariants asserted here are precisely about what generations
// exist, so a warm/reused device would make a false pass indistinguishable
// from a true one.
//
// On Kubevirt, grub options cap dom0/eve/ctrd vcpus to speed up cluster
// formation, mirroring tests/cluster/cluster_test.go's
// clusterDeviceRequirements. They are omitted on the other hypervisors, where
// there is no cluster to form.
func purgeDeviceRequirements(devName string, withTPM bool,
	filesystem evetest.Filesystem, hv evetest.Hypervisor) evetest.RequireEdgeDevice {
	req := evetest.RequireEdgeDevice{
		Name:              devName,
		WithTPM:           withTPM,
		WithHypervisor:    hv,
		DeviceReusePolicy: evetest.CreateFromScratchWithLiveImage,
		WithFilesystem:    filesystem,
	}
	if hv == evetest.HypervisorKubevirt {
		req.WithGrubOptions = []string{
			"set_global hv_dom0_cpu_settings \"dom0_max_vcpus=4\"",
			"set_global hv_eve_cpu_settings \"eve_max_vcpus=3\"",
			"set_global hv_ctrd_cpu_settings \"ctrd_max_vcpus=3\"",
		}
	}
	return req
}

// vmShimApplication returns the ApplicationInstanceConfig for the app used
// throughout this suite: the standard evetest-ubuntu-ctr container image run
// with VirtualizationMode=HVM. On eve-k, HVM (rather than the
// container-native NOHYPER default) makes domainmgr's kube path create a
// VMIRS (hypervisor/kubevirt.go CreateReplicaVMIConfig) instead of a plain
// pod, so this "shim VM" is the cheapest fixture that exercises the
// VMIRS-lifecycle code this suite is testing. On kvm/xen the same config
// yields an ordinary qemu domain, which is what makes the two comparable.
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
