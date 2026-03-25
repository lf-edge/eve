// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const (
	// EveVirtTypeFile contains the virtualization type, i.e., kvm, xen or k
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

// GetAppKubeName returns name of the application used inside Kubernetes (for Pod or VMI).
func GetAppKubeName(displayName string, uuid uuid.UUID) string {
	appKubeName := displayName
	// Replace underscores with dashes for Kubernetes
	appKubeName = strings.ReplaceAll(appKubeName, "_", "-")
	// Remove special characters using regular expressions
	appKubeName = kubeNameForbiddenChars.ReplaceAllString(appKubeName, "")
	// Reduce combinations like '-.-' or '.-.' to a single dash
	appKubeName = kubeNameSeparators.ReplaceAllString(appKubeName, "-")
	appKubeName = strings.ToLower(appKubeName)
	const maxLen = KubeAppNameMaxLen - 1 - KubeAppNameUUIDSuffixLen
	if len(appKubeName) > maxLen {
		appKubeName = appKubeName[:maxLen]
	}
	return appKubeName + "-" + uuid.String()[:KubeAppNameUUIDSuffixLen]
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
	if strings.HasPrefix(suffix, "-") && len(suffix[1:]) == 5 {
		return kubeName, true
	}
	return "", false
}
