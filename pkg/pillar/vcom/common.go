// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcom

const (
	// HostVPort is the port on which the vsock listens on the host, this is
	// the port that the guest should connect. This is vsock port and it won't
	// block the usage of the same port in other types of sockets like TCP.
	HostVPort = 2000
	// TpmEKHandle is handle used by EVE to store the Endorsement Key (EK) in TPM.
	TpmEKHandle = 0x81000001
	// TpmSRKHandle is handle used by EVE to store the Storage Root Key (SRK) in TPM.
	TpmSRKHandle = 0x81000002
	// TpmAIKHandle is handle used by EVE to store the Attestation Identity Key (AIK) in TPM.
	TpmAIKHandle = 0x81000003
	// TpmDeviceKeyHandle is handle used by EVE to store the Device Key in TPM.
	TpmDeviceKeyHandle = 0x817FFFFF
	// This is acroding to TCG TPM v2.0 Provisioning Guidance,
	// Table 2: Reserved Handles for TPM Provisioning Fundamental Elements
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	TpmEKCertHandle = 0x01C00002
)
