// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package base

import (
	"os"
	"regexp"
	"strings"
)

const (
	// EveVirtTypeFile contains the virtualization type, ie kvm, xen or kubevirt
	EveVirtTypeFile = "/run/eve-hv-type"
	// Max length of the name in Kubernetes App plus app's UUID prefix
	EveKubeAppMaxNameLen = 32
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

// ConvToKubeName - convert to lowercase and underscore to dash,
// and truncate to 32 characters
func ConvToKubeName(inName string) string {
	// Replace underscores with dashes for Kubernetes
	maxLen := EveKubeAppMaxNameLen
	if len(inName) < maxLen {
		maxLen = len(inName)
	}
	processedString := strings.ReplaceAll(inName[:maxLen], "_", "-")

	// Remove special characters using regular expressions
	reg := regexp.MustCompile("[^a-zA-Z0-9-.]")
	processedString = reg.ReplaceAllString(processedString, "")

	// Reduce combinations like '-.-' or '.-.' to a single dash
	processedString = regexp.MustCompile("[.-]+").ReplaceAllString(processedString, "-")

	lowercaseString := strings.ToLower(processedString)
	return lowercaseString
}
