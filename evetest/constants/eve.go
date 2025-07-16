// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package constants

const (
	// DefaultEVEDeviceCPUs is the default number of virtual CPUs for an EVE device VM.
	DefaultEVEDeviceCPUs = 4
	// DefaultEVEDeviceRAMInMB is the default amount of RAM in megabytes for an EVE device VM.
	DefaultEVEDeviceRAMInMB = 8192
	// DefaultEVEDeviceDiskSizeInMB is the default disk size in megabytes for an EVE device VM.
	DefaultEVEDeviceDiskSizeInMB = 28576
)

const (
	// EVESSHPublickKey : public key used for SSH access into EVE.
	// This is the content of evetest/cert/eve_rsa.pub
	EVESSHPublickKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC+H1RQUqHjFBJg" +
		"GpslC73XsLz8Fg5WpNPble9naKyWz1Um8D2bOtQK/yguCImPeBYc" +
		"H7/73z8dtC6d+dT0UF26+o7Vh6RN/U2X/5nkaZr7oM5QwwZTsD7N" +
		"d2Szww9wrRhXvpV0aFgUBDM9BIF1qBQxLNd+Jp8uttrgF3zj/cm7" +
		"+SXllG54sv8WFBMfTX7J8cQ1jxLyp/Sc6PXK0zBaVzZwhmCCmI6C" +
		"IzJK6ahMRgXm2vSP6doYibkB3ETSskaCXSHxDiZoaQK2ZY+GqNZk" +
		"Uusbau43MXVPTiJknXqUcmXhQmwyMSltQ3G54jcgn4TDObSQnW7v" +
		"GdLI7zIEAHnk5D1BmKzQUBh5aRLdhBtb6T3uvVtAqGgnXWKD+d2G" +
		"jMiy4G31zfIlArvC3G8LxwsDoxQL0XKaFjnEmXIptVXC68zq+laI" +
		"M8YGDDOCEc6RfczP7lA4p6rv0gQUfTNqy0P3a4ulvIDb4hET1Gkh" +
		"+Azkuw1do9NIhXPxDBmPdkTnKwJv6XelpdCPCw1QT5o7WdOkUgor" +
		"f/e03jGDnnn1QBWpSPB9gLB/oDmT/Gzm8tCYaq7ggwYUq1fSMBvn" +
		"bFaclH1KVcC2Gwn8UPLt9HHa/mGywuISZYl3gy7ztlKyAjHEZH05" +
		"3U7I8OaMvv/CFo9aR4Teeb5848REZYAes+yJIz3lJV1K5Q=="

	// EVESSHPrivateKey : private key used for SSH access into EVE.
	// This is the content of evetest/cert/eve_rsa
	EVESSHPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
1Kj1q1XgH7MAAAAAAQID
-----END OPENSSH PRIVATE KEY-----
`
)

const (
	// QemuArtifactsDirname : name of the directory under which the QEMU provider
	// outputs artifacts (device console output, qmp events, etc.).
	QemuArtifactsDirname = "evetest-qemu-vms"
)
