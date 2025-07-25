// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package vcom

import etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"

const (
	// HostVPort is the port on which the vsock listens on the host, this is
	// the port that the guest should connect. This is vsock port and it won't
	// block the usage of the same port in other types of sockets like TCP.
	HostVPort = 2000
	// TpmEKHandle is handle used by EVE to store the Endorsement Key (EK) in TPM.
	TpmEKHandle = etpm.TpmEKHdl
	// TpmSRKHandle is handle used by EVE to store the Storage Root Key (SRK) in TPM.
	TpmSRKHandle = etpm.TpmSRKHdl
	// TpmAIKHandle is handle used by EVE to store the Attestation Identity Key (AIK) in TPM.
	TpmAIKHandle = etpm.TpmAIKHdl
	// TpmEcdhHandle is handle used by EVE to store the ECDH signing key in TPM
	TpmEcdhHandle = etpm.TpmEcdhKeyHdl
	// TpmEKCertHandle value is acroding to TCG TPM v2.0 Provisioning Guidance,
	// Table 2: Reserved Handles for TPM Provisioning Fundamental Elements
	// https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
	TpmEKCertHandle = 0x01C00002
)
