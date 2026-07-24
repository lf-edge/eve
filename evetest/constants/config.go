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

	// ColorOutputEnv determines whether framework log output is colorized
	// with ANSI escape codes. When unset, the Makefile (or, as a fallback,
	// the container entrypoint) enables colors only if stdout is attached
	// to a terminal, so that piped or redirected output stays free of
	// escape codes.
	ColorOutputEnv = "COLOR_OUTPUT"

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

	// HomeDirEnv specifies the evetest data directory on the host ($HOME/.evetest).
	// It is passed by the Makefile as EVETEST_HOME=$(HOME)/.evetest and must be
	// bind-mounted into the container at the same path so that Docker bind-mounts
	// issued from inside the container (e.g. for rootfs extraction) resolve
	// correctly on the host.
	// This is read by the evetest container.
	HomeDirEnv = "HOME"

	// PreferredArchEnv specifies the preferred CPU architecture for EVE devices.
	// Accepted values: "amd64", "arm64" (case-insensitive).
	// The framework will use this architecture if the broker supports it;
	// otherwise it falls back to whichever architecture is available.
	// This is read by the evetest container.
	PreferredArchEnv = "PREFERRED_ARCH"

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
	// Maximum allowed prefix length is /30.
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

	// BrokerProxmoxAPIURLEnv specifies the Proxmox VE REST API base URL
	// (e.g. "https://192.168.1.50:8006/api2/json"). Read by evetest-broker when
	// proxmox is the selected device provider.
	BrokerProxmoxAPIURLEnv = "BROKER_PROXMOX_API_URL"

	// BrokerProxmoxPasswordEnv specifies the password for the "root@pam" Proxmox
	// user. Read by evetest-broker for the proxmox provider. Must authenticate as
	// the literal root@pam user, not an API token: Proxmox hardcodes several VM
	// config options (e.g. "hookscript", "args") as settable only by a real
	// "root@pam" session, regardless of a token's assigned privileges/ACLs :(
	BrokerProxmoxPasswordEnv = "BROKER_PROXMOX_PASSWORD"

	// BrokerProxmoxNodeEnv specifies the Proxmox node name on which to create VMs
	// (e.g. "pve"). Optional: if unset, the broker auto-detects the node on a
	// single-node installation; it is only required for multi-node clusters.
	// Read by evetest-broker for the proxmox provider.
	BrokerProxmoxNodeEnv = "BROKER_PROXMOX_NODE"

	// BrokerProxmoxStorageEnv specifies the Proxmox storage ID used for VM disks
	// (e.g. "local-lvm"). Read by evetest-broker for the proxmox provider.
	BrokerProxmoxStorageEnv = "BROKER_PROXMOX_STORAGE"

	// BrokerProxmoxImportStorageEnv specifies the Proxmox storage ID (with the
	// "import" content type enabled, e.g. "local") that VM disk images are
	// uploaded to before being imported into the VM disk storage.
	// Defaults to "local". Read by evetest-broker for the proxmox provider.
	BrokerProxmoxImportStorageEnv = "BROKER_PROXMOX_IMPORT_STORAGE"

	// BrokerProxmoxTLSSkipVerifyEnv, when set to a truthy value, disables TLS
	// certificate verification for the Proxmox API connection (useful with the
	// default self-signed PVE certificate). Read by evetest-broker for the
	// proxmox provider.
	BrokerProxmoxTLSSkipVerifyEnv = "BROKER_PROXMOX_TLS_SKIP_VERIFY"

	// BrokerImageDirEnv specifies the directory where evetest-broker
	// should store the EVE and SDN disk images.
	BrokerImageDirEnv = "BROKER_IMAGE_DIR"

	// BrokerPprofPortEnv specifies the port on which the broker exposes its Go
	// net/http/pprof debug endpoint (listening on all interfaces). 0 (default)
	// disables it. Read by evetest-broker.
	BrokerPprofPortEnv = "BROKER_PPROF_PORT"

	// BrokerMaxClientsEnv specifies the maximum number of concurrent evetest clients
	// the broker will serve. Once this many clients are connected, Connect calls
	// for brand-new clients fail with an error until a session frees up (reconnects
	// of already-connected clients are never blocked by this limit).
	// -1 (default) means unlimited. Read by evetest-broker.
	BrokerMaxClientsEnv = "BROKER_MAX_CLIENTS"

	// BrokerDockerImageRetentionEnv specifies how long (in minutes) an unused
	// Docker image (not referenced by any existing container) is kept before
	// the broker's periodic cleanup removes it. This lets a pulled EVE/SDN
	// image be reused across test runs for a while, without letting years'
	// worth of old image versions accumulate on disk. Read by evetest-broker.
	BrokerDockerImageRetentionEnv = "BROKER_DOCKER_IMAGE_RETENTION"

	// BrokerDockerDiskUsageThresholdEnv specifies the disk usage percentage
	// (on the filesystem backing Docker's storage) at or above which the
	// broker aggressively evicts the oldest unused Docker images, regardless
	// of BrokerDockerImageRetentionEnv, until usage drops back under it.
	// Read by evetest-broker.
	BrokerDockerDiskUsageThresholdEnv = "BROKER_DOCKER_DISK_USAGE_THRESHOLD"

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

	// RegistryMirrorDockerEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed, e.g. "http://[fd11::5]:5000") for docker.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorDockerEnv = "REGISTRY_MIRROR_DOCKER"

	// RegistryMirrorGhcrEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed) for ghcr.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorGhcrEnv = "REGISTRY_MIRROR_GHCR"

	// RegistryMirrorQuayEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed) for quay.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorQuayEnv = "REGISTRY_MIRROR_QUAY"

	// RegistryMirrorK8sEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed) for registry.k8s.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorK8sEnv = "REGISTRY_MIRROR_K8S"

	// RegistryMirrorGcrEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed) for gcr.io image pulls.
	// This is read by the evetest container.
	RegistryMirrorGcrEnv = "REGISTRY_MIRROR_GCR"

	// RegistryMirrorMcrEnv specifies one or more comma-separated
	// pull-through cache URLs ([scheme://]host:port[/path], IPv6 hosts
	// bracketed) for mcr.microsoft.com image pulls.
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
	DefaultSDNRepo = "lfedge/evetest-sdn"

	// DefaultAdamVersion specifies the Adam version to use by default.
	DefaultAdamVersion = "0.0.75"

	// DefaultSDNVersion specifies the SDN version to use by default.
	DefaultSDNVersion = "1.0"

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
	// libvirt-setup-broker-user Makefile target) because /home is typically a separate,
	// larger partition than /var (where libvirt's stock storage pool lives),
	// and /home/eve-broker is already accessible to libvirt-qemu via the
	// group memberships configured by libvirt-setup-broker-user.
	DefaultBrokerImageDir = "/home/eve-broker/images"

	// DefaultBrokerMaxClients means "unlimited" -- no cap on concurrent clients.
	DefaultBrokerMaxClients = -1

	// DefaultBrokerDockerImageRetentionMinutes is 7 days.
	DefaultBrokerDockerImageRetentionMinutes = 7 * 24 * 60

	// DefaultBrokerDockerDiskUsageThresholdPercent triggers aggressive Docker
	// image cleanup once the filesystem backing Docker's storage is at least
	// this full.
	DefaultBrokerDockerDiskUsageThresholdPercent = 80
)

// InitViperConfig initializes the Viper configuration with default values.
func InitViperConfig() {
	// Viper expects the prefix without the trailing underscore.
	viper.SetEnvPrefix(strings.TrimSuffix(EnvPrefix, "_"))
	viper.AutomaticEnv()

	// Logging
	viper.SetDefault(LogLevelEnv, DefaultLogLevel)
	// The Makefile and the entrypoint script override this based on TTY
	// presence; the default only applies when the framework is run outside
	// the evetest container.
	viper.SetDefault(ColorOutputEnv, true)

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
	viper.SetDefault(BrokerPprofPortEnv, 0)
	viper.SetDefault(BrokerMaxClientsEnv, DefaultBrokerMaxClients)
	viper.SetDefault(BrokerDockerImageRetentionEnv, DefaultBrokerDockerImageRetentionMinutes)
	viper.SetDefault(BrokerDockerDiskUsageThresholdEnv, DefaultBrokerDockerDiskUsageThresholdPercent)

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

// LoadRegistryMirrors returns a map of registry hostname → mirror URLs for
// all per-registry mirror env vars that are currently set. Each env var may
// hold a comma-separated list of URLs (e.g. one IPv4 and one IPv6 address for
// the same mirror); use SelectRegistryMirror to pick one.
func LoadRegistryMirrors() map[string][]string {
	mirrors := make(map[string][]string)
	for _, e := range RegistryMirrorEntries {
		raw := viper.GetString(e.EnvVar)
		if raw == "" {
			continue
		}
		var urls []string
		for _, url := range strings.Split(raw, ",") {
			if url = strings.TrimSpace(url); url != "" {
				urls = append(urls, url)
			}
		}
		if len(urls) > 0 {
			mirrors[e.Registry] = urls
		}
	}
	return mirrors
}

// isIPv6MirrorURL reports whether a mirror URL's host is a bracketed IPv6
// literal (e.g. "http://[fd11::5]:5000"), as opposed to an IPv4 or hostname
// address.
func isIPv6MirrorURL(url string) bool {
	return strings.Contains(url, "://[")
}

// SelectRegistryMirror picks one address from a registry's configured mirror
// URLs (as returned by LoadRegistryMirrors).
//
// If ipv6Only is true, it returns the first IPv6 URL, or ok=false if none of
// the given addresses are IPv6 -- callers should treat that as "no mirror
// available" for this registry rather than falling back to an address the
// device can't reach.
//
// Otherwise it prefers the first non-IPv6 (IPv4/hostname) URL, falling back
// to the first URL of any kind if only IPv6 addresses are configured.
func SelectRegistryMirror(urls []string, ipv6Only bool) (url string, ok bool) {
	if ipv6Only {
		for _, u := range urls {
			if isIPv6MirrorURL(u) {
				return u, true
			}
		}
		return "", false
	}
	for _, u := range urls {
		if !isIPv6MirrorURL(u) {
			return u, true
		}
	}
	if len(urls) > 0 {
		return urls[0], true
	}
	return "", false
}

// RegistryMirrorEnvVar returns the env var name that configures the
// pull-through cache mirror for the given registry hostname.
func RegistryMirrorEnvVar(registry string) (string, bool) {
	for _, e := range RegistryMirrorEntries {
		if e.Registry == registry {
			return e.EnvVar, true
		}
	}
	return "", false
}
