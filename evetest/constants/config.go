// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package constants

import (
	"strings"

	"github.com/spf13/viper"
)

// Environment variable names used across the evetest framework.
const (
	// EnvPrefix : prefix used for environment variables used by evetest.
	EnvPrefix = "EVETEST_"

	// VersionEnv specifies the version of the evetest framework.
	// This is read from the VERSION file by Makefile and set inside
	// the evetest (and also inside the broker) container by Dockerfile.
	VersionEnv = "VERSION"

	// LogLevelEnv sets the log level for the evetest framework (not EVE).
	// This is read by both the evetest container and the broker.
	LogLevelEnv = "LOG_LEVEL"

	// APIAddressEnv specifies the IP address on which the evetest container exposes
	// its gRPC API.
	// This is used by the evetest CLI to connect to a running evetest instance.
	APIAddressEnv = "API_ADDRESS"

	// APIPortEnv specifies the port on which the evetest container exposes
	// its gRPC API.
	// This is used by the evetest CLI to connect to a running evetest instance.
	APIPortEnv = "API_PORT"

	// SDNPortEnv specifies the port on which the SDN exposes its gRPC API.
	// This is read by the SDN, the evetest broker and the evetest container.
	SDNPortEnv = "SDN_PORT"

	// BrokerAddressEnv specifies the address (IP or hostname) on which the evetest-broker
	// exposes its gRPC API.
	// This is read by the evetest container.
	BrokerAddressEnv = "BROKER_ADDRESS"

	// BrokerPortEnv specifies the port on which the evetest-broker exposes its gRPC API.
	// This is read by the broker and the evetest container.
	BrokerPortEnv = "BROKER_PORT"

	// TestNameEnv specifies the name of the test or test suite to run.
	// This is read by the evetest container.
	TestNameEnv = "NAME"

	// SuiteMaxFailuresEnv defines how many test failures are tolerated before
	// aborting a test suite.
	// A negative number means run all tests regardless of failures.
	// This is read by the evetest container.
	SuiteMaxFailuresEnv = "SUITE_MAX_FAILURES"

	// PauseOnCheckpointEnv defines the checkpoint name (set via evetest.Checkpoint())
	// where test execution should pause.
	// This is read by the evetest container.
	PauseOnCheckpointEnv = "PAUSE_ON_CHECKPOINT"

	// PauseOnFailureEnv determines whether to pause the container after a test failure
	// to allow for manual inspection. Use 'evetest continue' or 'evetest exit'
	// to resume/stop.
	// This is read by the evetest container.
	PauseOnFailureEnv = "PAUSE_ON_FAILURE"

	// EVEVersionEnv specifies the version of EVE to test.
	// If unset, the EVE version from the local repository is used (including
	// any uncommitted changes).
	// This is read by the evetest container.
	EVEVersionEnv = "EVE_VERSION"

	// EVERepoEnv defines the container image repository to use for pulling EVE images.
	// This is read by the evetest container.
	EVERepoEnv = "EVE_REPO"

	// PreferredArchEnv specifies the preferred CPU architecture for EVE devices.
	// Accepted values: "amd64", "arm64" (case-insensitive).
	// The framework will use this architecture if the broker supports it;
	// otherwise it falls back to whichever architecture is available.
	// This is read by the evetest container.
	PreferredArchEnv = "PREFERRED_ARCH"

	// EVEImgRetentionEnv defines the retention time (in minutes) for an EVE image pulled
	// by the broker. This allows reusing the same image in future test runs.
	// This is read by the broker.
	EVEImgRetentionEnv = "EVE_IMG_RETENTION_MINUTES"

	// AdamVersionEnv specifies the version of the Adam controller to use.
	// This is read by the evetest container.
	AdamVersionEnv = "ADAM_VERSION"

	// AdamRepoEnv defines the repository to use for pulling Adam images.
	// This is read by the evetest container.
	AdamRepoEnv = "ADAM_REPO"

	// SDNVersionEnv specifies the version of the SDN emulator to use.
	// This is read by the evetest container.
	SDNVersionEnv = "SDN_VERSION"

	// SDNRepoEnv defines the container repository to use for pulling SDN images.
	SDNRepoEnv = "SDN_REPO"

	// SDNUplinkIPv4SubnetEnv specifies the IPv4 subnet to use for allocating IPv4
	// addresses for SDN VM uplink interfaces.
	// Maximum allowed prefix length is /29.
	// This is read by evetest-broker.
	SDNUplinkIPv4SubnetEnv = "SDN_UPLINK_IPV4_SUBNET"

	// SDNUplinkIPv6SubnetEnv specifies the IPv6 subnet to use for allocating IPv6
	// addresses for SDN VM uplink interfaces.
	// This is read by evetest-broker.
	SDNUplinkIPv6SubnetEnv = "SDN_UPLINK_IPV6_SUBNET"

	// BrokerProviderEnv defines the device provider to use.
	// This is read by evetest-broker.
	BrokerProviderEnv = "BROKER_DEVICE_PROVIDER"

	// BrokerLibvirtURIEnv specifies the URI to configure for the libvirt device provider.
	// This is read by evetest-broker when libvirt is the device provider selected.
	// NOT YET SUPPORTED: LibvirtProvider always uses "qemu:///system" URI.
	BrokerLibvirtURIEnv = "BROKER_LIBVIRT_URI"

	// BrokerImageDirEnv specifies the directory where evetest-broker
	// should store the EVE and SDN disk images.
	BrokerImageDirEnv = "BROKER_IMAGE_DIR"

	// ExternalArtifactDirEnv specifies a host-side directory path where all test
	// artifacts should be collected.
	// This variable is optional and may be set by the user.
	ExternalArtifactDirEnv = "COLLECT_ARTIFACTS"

	// CollectCoverageEnv enables collection of Go coverage profiles from EVE devices.
	// When set together with EVETEST_COLLECT_ARTIFACTS, the framework will send SIGUSR2
	// to zedbox and archive /persist/coverage before each device reboot and at test
	// completion. Requires EVE to be built with COVER=y.
	CollectCoverageEnv = "COLLECT_COVERAGE"

	// InternalArtifactDirEnv specifies a container-internal directory path where all
	// test artifacts are written.
	// This variable is always set by the container entrypoint and must not be set
	// by the user.
	InternalArtifactDirEnv = "ARTIFACT_DIR"

	// RegistryMirrorDockerEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for docker.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorDockerEnv = "REGISTRY_MIRROR_DOCKER"

	// RegistryMirrorGhcrEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for ghcr.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorGhcrEnv = "REGISTRY_MIRROR_GHCR"

	// RegistryMirrorQuayEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for quay.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorQuayEnv = "REGISTRY_MIRROR_QUAY"

	// RegistryMirrorK8sEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for registry.k8s.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorK8sEnv = "REGISTRY_MIRROR_K8S"

	// RegistryMirrorGcrEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for gcr.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorGcrEnv = "REGISTRY_MIRROR_GCR"

	// RegistryMirrorMcrEnv specifies a pull-through cache URL
	// ([scheme://]host:port[/path]) for mcr.microsoft.com image pulls.
	// This is read by the evetest container.
	RegistryMirrorMcrEnv = "REGISTRY_MIRROR_MCR"
)

// Default values for the corresponding environment variables.
const (
	// DefaultAPIPort is the default port for evetest container gRPC API.
	DefaultAPIPort = 50021

	// DefaultSDNPort is the default port for the SDN gRPC API.
	DefaultSDNPort = 50121

	// DefaultBrokerPort is the default port for the broker gRPC API.
	DefaultBrokerPort = 50221

	// DefaultLogLevel is the default log level for the evetest framework.
	DefaultLogLevel = "INFO"

	// DefaultSuiteMaxFailures is the default value for how many test failures
	// are allowed in a suite.
	DefaultSuiteMaxFailures = 1

	// DefaultPreferredArch is the default preferred CPU architecture for EVE devices.
	DefaultPreferredArch = "amd64"

	// DefaultEVERepo is the default EVE image repository.
	DefaultEVERepo = "lfedge/eve"

	// DefaultAdamRepo is the default Adam controller image repository.
	DefaultAdamRepo = "lfedge/adam"

	// DefaultSDNRepo is the default SDN image repository.
	// TODO: change to lfedge once the repo is created
	DefaultSDNRepo = "milan4zededa/evetest-sdn"

	// DefaultEVEImgRetentionMinutes is the default time to retain unused EVE images.
	DefaultEVEImgRetentionMinutes = 60

	// DefaultAdamVersion specifies the Adam version to use by default.
	DefaultAdamVersion = "0.0.75"

	// DefaultSDNVersion specifies the SDN version to use by default.
	DefaultSDNVersion = "v0.0.1"

	// DefaultSDNUplinkIPv4Subnet species the IPv4 subnet used for SDN uplink
	// interfaces by default.
	DefaultSDNUplinkIPv4Subnet = "192.168.170.0/24"

	// DefaultSDNUplinkIPv6Subnet species the IPv6 subnet used for SDN uplink
	// interfaces by default.
	DefaultSDNUplinkIPv6Subnet = "fd11:778b:03dd:2222::/64"

	// DefaultBrokerProvider specifies the device provider used by evetest-broker
	// by default.
	DefaultBrokerProvider = "libvirt"

	// DefaultBrokerLibvirtURI specifies the URI configured for the Libvirt provider
	// by default.
	DefaultBrokerLibvirtURI = "qemu:///system"

	// DefaultBrokerImageDir is the default location for EVE and SDN disk images.
	// It is under the home directory of the eve-broker user (created by the
	// setup-broker-user Makefile target) because /home is typically a separate,
	// larger partition than /var (where libvirt's stock storage pool lives),
	// and /home/eve-broker is already accessible to libvirt-qemu via the
	// group memberships configured by setup-broker-user.
	DefaultBrokerImageDir = "/home/eve-broker/images"
)

// InitViperConfig initializes the Viper configuration with default values.
func InitViperConfig() {
	// Viper expects the prefix without the trailing underscore.
	viper.SetEnvPrefix(strings.TrimSuffix(EnvPrefix, "_"))
	viper.AutomaticEnv()

	// Logging
	viper.SetDefault(LogLevelEnv, DefaultLogLevel)

	// gRPC API ports and addresses
	viper.SetDefault(APIAddressEnv, "")
	viper.SetDefault(APIPortEnv, DefaultAPIPort)
	viper.SetDefault(SDNPortEnv, DefaultSDNPort)
	viper.SetDefault(BrokerAddressEnv, "")
	viper.SetDefault(BrokerPortEnv, DefaultBrokerPort)

	// Test control
	viper.SetDefault(TestNameEnv, "") // No default, must be provided
	viper.SetDefault(SuiteMaxFailuresEnv, DefaultSuiteMaxFailures)
	viper.SetDefault(PauseOnCheckpointEnv, "")
	viper.SetDefault(PauseOnFailureEnv, false)
	viper.SetDefault(CollectCoverageEnv, false)

	// EVE image config
	viper.SetDefault(EVEVersionEnv, "") // Empty = derive from repo
	viper.SetDefault(EVERepoEnv, DefaultEVERepo)
	viper.SetDefault(PreferredArchEnv, DefaultPreferredArch)
	viper.SetDefault(EVEImgRetentionEnv, DefaultEVEImgRetentionMinutes)

	// Adam image config
	viper.SetDefault(AdamVersionEnv, DefaultAdamVersion)
	viper.SetDefault(AdamRepoEnv, DefaultAdamRepo)

	// SDN image config
	viper.SetDefault(SDNVersionEnv, DefaultSDNVersion)
	viper.SetDefault(SDNRepoEnv, DefaultSDNRepo)
	viper.SetDefault(SDNUplinkIPv4SubnetEnv, DefaultSDNUplinkIPv4Subnet)
	viper.SetDefault(SDNUplinkIPv6SubnetEnv, DefaultSDNUplinkIPv6Subnet)

	// Broker config
	viper.SetDefault(BrokerProviderEnv, DefaultBrokerProvider)
	viper.SetDefault(BrokerLibvirtURIEnv, DefaultBrokerLibvirtURI)
	viper.SetDefault(BrokerImageDirEnv, DefaultBrokerImageDir)

	// Per-registry pull-through cache mirrors
	for _, e := range RegistryMirrorEntries {
		viper.SetDefault(e.EnvVar, "")
	}
}

// RegistryMirrorEntry maps a registry hostname to the env var that configures
// its pull-through cache mirror URL.
type RegistryMirrorEntry struct {
	Registry string
	EnvVar   string
}

// RegistryMirrorEntries lists all registries for which evetest supports
// per-registry pull-through cache configuration.
var RegistryMirrorEntries = []RegistryMirrorEntry{
	{"docker.io", RegistryMirrorDockerEnv},
	{"ghcr.io", RegistryMirrorGhcrEnv},
	{"quay.io", RegistryMirrorQuayEnv},
	{"registry.k8s.io", RegistryMirrorK8sEnv},
	{"gcr.io", RegistryMirrorGcrEnv},
	{"mcr.microsoft.com", RegistryMirrorMcrEnv},
}

// LoadRegistryMirrors returns a map of registry hostname → mirror URL
// for all per-registry mirror env vars that are currently set.
func LoadRegistryMirrors() map[string]string {
	mirrors := make(map[string]string)
	for _, e := range RegistryMirrorEntries {
		if url := viper.GetString(e.EnvVar); url != "" {
			mirrors[e.Registry] = url
		}
	}
	return mirrors
}
