// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"os"
	"regexp"
	"strings"

	uuid "github.com/satori/go.uuid"
)

const (
	// EveVirtTypeFile contains the virtualization type, ie kvm, xen or kubevirt
	EveVirtTypeFile = "/run/eve-hv-type"
	// KubeAppNameMaxLen limits the length of the app name for Kubernetes.
	// This also includes the appended UUID prefix.
	KubeAppNameMaxLen = 32
	// KubeAppNameUUIDPrefixLen : length of the app UUID prefix appended to the app
	// name for Kubernetes.
	KubeAppNameUUIDPrefixLen = 5
	// VMIPodNamePrefix : prefix added to name of every pod created to run VM.
	VMIPodNamePrefix = "virt-launcher-"
	// InstallOptionEtcdSizeGB grub option at install time.  Size of etcd volume in GB.
	InstallOptionEtcdSizeGB = "eve_install_kubevirt_etcd_sizeGB"
	// DefaultEtcdSizeGB default for InstallOptionEtcdSizeGB
	DefaultEtcdSizeGB uint32 = 10
)

// IsHVTypeKube - return true if the EVE image is kube cluster type.
func IsHVTypeKube() bool {
	retbytes, err := os.ReadFile(EveVirtTypeFile)
	if err != nil {
		return false
	}

	if strings.Contains(string(retbytes), "kubevirt") {
		return true
	}
	return false
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
	const maxLen = KubeAppNameMaxLen - 1 - KubeAppNameUUIDPrefixLen
	if len(appKubeName) > maxLen {
		appKubeName = appKubeName[:maxLen]
	}
	return appKubeName + "-" + uuid.String()[:KubeAppNameUUIDPrefixLen]
}

// GetVMINameFromVirtLauncher : get VMI name from the corresponding Kubevirt
// launcher pod name.
func GetVMINameFromVirtLauncher(podName string) (vmiName string, isVirtLauncher bool) {
	if !strings.HasPrefix(podName, VMIPodNamePrefix) {
		return "", false
	}
	vmiName = strings.TrimPrefix(podName, VMIPodNamePrefix)
	lastSep := strings.LastIndex(vmiName, "-")
	if lastSep != -1 {
		vmiName = vmiName[:lastSep]
	}
	return vmiName, true
}
