// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const (
	// EveVirtTypeFile contains the virtualization type, i.e., kvm or k
	EveVirtTypeFile = "/run/eve-hv-type"
	// KubeAppNameMaxLen limits the length of the app name for Kubernetes.
	// This also includes the appended UUID prefix.
	KubeAppNameMaxLen = 32
	// KubeAppNameUUIDSuffixLen : number of characters taken from the app UUID and appended
	// to the app name for Kubernetes (to avoid name collisions between apps of the same
	// DisplayName, see GetAppKubeName).
	KubeAppNameUUIDSuffixLen = 5
	// VMIPodNamePrefix : prefix added to name of every pod created to run VM.
	VMIPodNamePrefix = "virt-launcher-"
	// InstallOptionEtcdSizeGB grub option at install time.  Size of etcd volume in GB.
	InstallOptionEtcdSizeGB = "eve_install_k3s_etcd_sizeGB"
	// DefaultEtcdSizeGB default for InstallOptionEtcdSizeGB
	DefaultEtcdSizeGB uint32 = 10
	// EtcdVolBlockSizeBytes is the block size for the etcd volume
	EtcdVolBlockSizeBytes = uint64(4 * 1024)
	// KubevirtHypervisorName is the name of the imaginary EVE 'k' hypervisor
	KubevirtHypervisorName = "k"
)

// IsHVTypeKube - return true if the current EVE image is kube cluster type.
func IsHVTypeKube() bool {
	retbytes, err := os.ReadFile(EveVirtTypeFile)
	if err != nil {
		return false
	}

	return strings.TrimSpace(string(retbytes)) == KubevirtHypervisorName
}

// IsVersionHVTypeKube - return true if the EVE version string is kube cluster type.
func IsVersionHVTypeKube(baseOsVersion string) (bool, error) {
	hv, err := versionToHVType(baseOsVersion)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(hv) == KubevirtHypervisorName, nil
}

// Returns HVType from the version string.
// Assumes HVType is before the last dash i.e.,
// FULL_VERSION:=$(ROOTFS_VERSION)-$(HV)-$(ZARCH)
func versionToHVType(baseOsVersion string) (string, error) {
	comp := strings.Split(baseOsVersion, "-")
	num := len(comp)
	if num < 3 {
		return "", fmt.Errorf("Short baseOsVersion string: %s",
			baseOsVersion)
	}
	return comp[num-2], nil
}

var (
	kubeNameForbiddenChars = regexp.MustCompile("[^a-zA-Z0-9-.]")
	kubeNameSeparators     = regexp.MustCompile("[.-]+")
)

// SanitizeKubeName converts an arbitrary display name into a DNS-1123-compatible
// fragment usable inside a Kubernetes object name: underscores become dashes,
// other forbidden characters are dropped, runs of '.'/'-' collapse to a single
// dash, and the result is lowercased. It does NOT guarantee uniqueness - callers
// that need a unique object name must append a discriminator (e.g. a UUID suffix).
func SanitizeKubeName(displayName string) string {
	name := strings.ReplaceAll(displayName, "_", "-")
	name = kubeNameForbiddenChars.ReplaceAllString(name, "")
	name = kubeNameSeparators.ReplaceAllString(name, "-")
	return strings.ToLower(name)
}

// GetAppKubeName returns name of the application used inside Kubernetes (for Pod or VMI).
func GetAppKubeName(displayName string, uuid uuid.UUID) string {
	appKubeName := SanitizeKubeName(displayName)
	const maxLen = KubeAppNameMaxLen - 1 - KubeAppNameUUIDSuffixLen
	if len(appKubeName) > maxLen {
		appKubeName = appKubeName[:maxLen]
	}
	return appKubeName + "-" + uuid.String()[:KubeAppNameUUIDSuffixLen]
}

// GetAppKubeNameWithPurge returns the Kubernetes name for an app including a purge counter
// suffix to ensure uniqueness across purge cycles. This prevents AlreadyExists collisions
// in the Kubernetes API when the old ReplicaSet is still terminating during a new purge cycle.
// Format: <appKubeName>-<purgeCounter>  (e.g. "myapp-027a9-3")
func GetAppKubeNameWithPurge(displayName string, id uuid.UUID, purgeCounter uint32) string {
	return GetAppKubeName(displayName, id) + "-" + strconv.FormatUint(uint64(purgeCounter), 10)
}

// kubeAppUUIDSeed seeds the v5 UUID derivation for directly-deployed Kubernetes workloads.
// It is a fixed constant so the derivation is stable across reboots, nodes, and EVE versions.
var kubeAppUUIDSeed = uuid.NewV5(uuid.NamespaceOID, "eve-kube-app-network-id")

// rsPodSuffix matches the 5-character lowercase-alphanumeric suffix that the ReplicaSet
// controller appends to pod names ("<ownerName>-<suffix>").
var rsPodSuffix = regexp.MustCompile(`^[a-z0-9]{5}$`)

// KubeAppUUID derives a stable, cluster-consistent synthetic appUUID for a directly-deployed
// Kubernetes workload (helm/raw yaml) that has no EVE controller-assigned UUID. It is a pure
// function of (namespace, ownerName) so every cluster node derives the identical value —
// which keeps the ClusterDeterministic MAC stable across reboot and migration.
func KubeAppUUID(namespace, ownerName string) uuid.UUID {
	return uuid.NewV5(kubeAppUUIDSeed, namespace+"/"+ownerName)
}

// KubePodMatchesOwner reports whether podName is either an ownerless bare Pod (whose synthesized
// ownerName is the pod name itself) or a pod of the bare ReplicaSet ownerName, with the form
// "<ownerName>-<5 lowercase-alnum chars>". Validating the suffix shape (rather than a plain
// prefix check) disambiguates nested owner names such as "app" vs "app-foo":
// "app-foo-x2k4p" matches only "app-foo", since "foo-x2k4p" is not a valid suffix.
func KubePodMatchesOwner(podName, ownerName string) bool {
	if ownerName == "" {
		return false
	}
	if podName == ownerName {
		return true
	}
	prefix := ownerName + "-"
	if !strings.HasPrefix(podName, prefix) {
		return false
	}
	return rsPodSuffix.MatchString(podName[len(prefix):])
}

// GetVMINameFromVirtLauncher extracts VMI name and ReplicaSet name from a Kubevirt
// launcher pod name.
// Pod name format: virt-launcher-<vmi-name>-<5-char-pod-suffix>
// VMI name format: <replicaset-name>-<5-char-random-suffix>
// Returns:
//   - vmiName: the actual VMI name (e.g., "ubuntu-cloudimg-vm-ff9d59r58j") for virtctl commands
//   - rsName: the ReplicaSet name (e.g., "ubuntu-cloudimg-vm-ff9d5") for app identification
//   - error: non-nil if podName is not a valid virt-launcher pod name
func GetVMINameFromVirtLauncher(podName string) (vmiName string, rsName string, err error) {
	if !strings.HasPrefix(podName, VMIPodNamePrefix) {
		return "", "", fmt.Errorf("not a virt-launcher pod: %s", podName)
	}
	name := strings.TrimPrefix(podName, VMIPodNamePrefix)
	lastSep := strings.LastIndex(name, "-")
	if lastSep == -1 || lastSep < 5 {
		return "", "", fmt.Errorf("invalid virt-launcher pod name format: %s", podName)
	}

	// Check if the last part is 5 bytes long (pod suffix)
	if len(name[lastSep+1:]) != 5 {
		return "", "", fmt.Errorf("invalid pod suffix length in: %s", podName)
	}

	// VMI name: remove only the pod suffix
	vmiName = name[:lastSep]

	// ReplicaSet name: remove both the pod suffix and the VMI random suffix (5 chars + dash)
	rsName = name[:lastSep-5]

	return vmiName, rsName, nil
}

// GetReplicaPodName : get the app name from the pod name for replica pods.
func GetReplicaPodName(displayName, podName string, uuid uuid.UUID) (kubeName string, isReplicaPod bool) {
	kubeName = GetAppKubeName(displayName, uuid)
	if !strings.HasPrefix(podName, kubeName) {
		return "", false
	}
	suffix := strings.TrimPrefix(podName, kubeName)
	if !strings.HasPrefix(suffix, "-") {
		return "", false
	}
	rest := suffix[1:] // strip leading "-"
	// Old format: {kubeName}-{5chars}
	if len(rest) == 5 {
		return kubeName, true
	}
	// New format with purge counter: {kubeName}-{purgeCounter}-{5chars}
	// Find the last "-" to separate the 5-char pod suffix from the purge counter.
	dashIdx := strings.LastIndex(rest, "-")
	if dashIdx >= 0 && len(rest[dashIdx+1:]) == 5 {
		if _, err := strconv.ParseUint(rest[:dashIdx], 10, 32); err == nil {
			return kubeName, true
		}
	}
	return "", false
}
