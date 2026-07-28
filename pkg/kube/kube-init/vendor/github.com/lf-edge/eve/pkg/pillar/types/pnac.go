// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	eveinfo "github.com/lf-edge/eve-api/go/info"
)

// PNACConfig : configuration for Port-based Network Access Control (PNAC).
type PNACConfig struct {
	// Indicates whether 802.1X authentication is enabled on the given port.
	Enabled bool

	// EAP identity (optional).
	// Even when certificate-based authentication is used (e.g., EAP-TLS),
	// an explicit EAP identity may be configured and does not need to match
	// the certificate’s DN or SAN attributes.
	// If no EAP identity is configured and a certificate-based EAP method
	// is used, EVE will derive the identity from the enrolled certificate,
	// preferring the subject common name (CN), or the SAN URI if CN is absent.
	EAPIdentity string `json:",omitempty"`

	// EAP method to use for authentication.
	// Currently, only EAP-TLS is supported; additional methods may be added in the future.
	EAPMethod eveconfig.EAPMethod `json:",omitempty"`

	// Certificate enrollment profile to use for authentication.
	// Relevant only when the selected EAP method requires a certificate (e.g., EAP-TLS).
	//
	// This field references the ProfileName of a certificate enrollment profile defined
	// in EdgeDevConfig (currently SCEP profiles only, see EdgeDevConfig.ScepProfiles).
	// While SCEP is the only supported enrollment protocol today, this field is
	// intended to reference any supported enrollment profile in the future.
	CertEnrollmentProfileName string `json:",omitempty"`

	// CACertPEM contains the trusted CA certificate chain in PEM format.
	//
	// The chain is used for verifying the authentication server's TLS certificate
	// during EAP-TLS (802.1X) authentication. Each certificate in the chain is
	// applied to validate the server presented by the switch, access point, or
	// other 802.1X authenticator to ensure a trusted TLS session.
	CACertPEM [][]byte `json:"pubsub-large-ProxyCertPEM"` //nolint:tagliatelle
}

const (
	// PNACStateDir is the directory containing per-interface PNAC state files.
	//
	// One file is created per network adapter, named after the interface
	// (e.g., /run/nim/pnac.state/eth0).
	//
	// Each file contains two fields:
	//   STATE: <CONNECTED> or <DISCONNECTED>
	//   TIMESTAMP: <Unix timestamp of the last state change>
	//
	// These files are updated automatically by the wpa_supplicant event watcher
	// to reflect the current port authentication state.
	PNACStateDir = "/run/nim/pnac.state"

	// WpaSupplicantCtrlSockDir is the directory containing per-interface
	// wpa_supplicant control sockets used by clients (e.g., wpa_cli) to send
	// commands and query status from the supplicant. Each interface has a
	// Unix domain socket named after the interface (e.g. /run/nim/wpa_supplicant/eth0).
	WpaSupplicantCtrlSockDir = "/run/nim/wpa_supplicant"
)

// PNACStatus : device-reported status of Port-Based Network Access Control (PNAC)
// using IEEE 802.1X on a specific network port.
type PNACStatus struct {
	// Indicates whether 802.1X authentication is enabled on the given port.
	Enabled bool

	// Current supplicant state as reported by the 802.1X client.
	State eveinfo.SupplicantState

	// Timestamp of the most recent successful 802.1X authentication.
	// Unset if authentication has not yet completed successfully.
	LastAuthTimestamp time.Time

	// Error reported by the supplicant during authentication.
	// May include authentication failures, certificate validation errors,
	// or timeouts.
	Error ErrorDescription
}

// PNACMetrics : IEEE 802.1X Port-Based Network Access Control (PNAC) metrics reported
// by the device for the given port.
type PNACMetrics struct {
	// Logical label identifying the network port associated with these metrics.
	LogicalLabel string
	// Total number of EAPOL frames received from the authenticator.
	EAPOLFramesRx uint64
	// Total number of EAPOL frames transmitted to the authenticator.
	EAPOLFramesTx uint64
	// Number of EAPOL-Start frames transmitted to initiate authentication.
	EAPOLStartFramesTx uint64
	// Number of EAPOL-Logoff frames transmitted to terminate authentication.
	EAPOLLogoffFramesTx uint64
	// Number of EAP-Response frames transmitted in response to authentication requests.
	EAPOLRespFramesTx uint64
	// Number of EAP-Request Identity frames received from the authenticator.
	EAPOLReqIDFramesRx uint64
	// Total number of other EAP-Request frames received from the authenticator.
	EAPOLReqFramesRx uint64
	// Number of invalid or malformed EAPOL frames received.
	EAPOLInvalidFramesRx uint64
	// Number of received EAPOL frames with incorrect length or truncated payload.
	EAPLengthErrorFramesRx uint64
}

// PNACMetricsList contains PNAC metrics for all network ports with IEEE 802.1X enabled.
type PNACMetricsList struct {
	Ports []PNACMetrics
}

// Key returns the pubsub message key for PNACMetricsList instance.
func (p PNACMetricsList) Key() string {
	return "global"
}
