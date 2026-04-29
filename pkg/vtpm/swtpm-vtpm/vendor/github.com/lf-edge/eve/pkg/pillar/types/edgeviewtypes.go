// Copyright (c) 2021-2022 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Types which feed in and out of the verifier

package types

import "time"

// Types for edge-view on device

const (
	// EdgeviewPath - path to edgeview files
	EdgeviewPath = "/run/edgeview/"
	// EdgeviewCfgFile - for configuration of edgeview
	EdgeviewCfgFile = EdgeviewPath + "edge-view-config"

	// EdgeViewJwtPrefix - jwt token prefix string
	EdgeViewJwtPrefix = "EvJWToken:"
	// EdgeViewExpPrefix - jwt expire prefix string
	EdgeViewExpPrefix = "EvJWTExp:"
	// EdgeViewMultiInstPrefix - multi-instance prefix string
	EdgeViewMultiInstPrefix = "EdgeViewMultiInst:"
	// EdgeViewCertPrefix - Edgeview Dispatcher Certs prefix string
	EdgeViewCertPrefix = "EvDepCerts:"
	// EdgeViewDevPolicyPrefix - Edgeview device policy prefix string
	EdgeViewDevPolicyPrefix = "EvDevPolicy:"
	// EdgeViewAppPolicyPrefix - Edgeview application policy prefix string
	EdgeViewAppPolicyPrefix = "EvAppPolicy:"
	// EdgeViewExtPolicyPrefix - Edgeview external policy prefix string
	EdgeViewExtPolicyPrefix = "EvExtPolicy:"
	// EdgeViewKubPolicyPrefix - Edgeview kubernetes policy prefix string
	EdgeViewKubPolicyPrefix = "EvKubPolicy:"
	// EdgeViewGenIDPrefix - Edgeview generation-ID prefix string
	EdgeViewGenIDPrefix = "EvGenID:"

	// EdgeviewJWTAlgo - JWT algorithm string
	EdgeviewJWTAlgo = "ES256"
	// EdgeviewJWTType - JWT type string
	EdgeviewJWTType = "JWT"

	// EdgeviewMaxInstNum - maximum instancess allowed
	EdgeviewMaxInstNum = 5
)

// EdgeviewConfig - edge-view config from controller
type EdgeviewConfig struct {
	JWToken     string      // JWT token for edge-view
	DispCertPEM [][]byte    // dispatcher certificates
	DevPolicy   EvDevPolicy // device policy
	AppPolicy   EvAppPolicy // app policy
	ExtPolicy   EvExtPolicy // external policy
	KubPolicy   EvKubPolicy // kubernetes policy
	GenID       uint32      // number of time started
}

// EvDevPolicy - edge-view policy for device access
// the 'Enabled' controls device side is allowed or not including debug commands
// With Enable Dev, can expend later for other policies
type EvDevPolicy struct {
	Enabled bool `json:"enabled"` // allow access to device
}

// EvAppPolicy - edge-view policy for application access
// the 'Enabled' controls all app access is allowed or not
// With Enable App, can expend later for other policies
type EvAppPolicy struct {
	Enabled bool `json:"enabled"` // allow access to apps
}

// EvExtPolicy - edge-view policy for external access
// the 'Enabled' controls all external access is allowed or not
// With Enable Ext, can expend later for other policies
type EvExtPolicy struct {
	Enabled bool `json:"enabled"` // allow access to external end-points
}

// EvKubPolicy - edge-view policy for kubernetes/kubectl access
// the 'Enabled' controls all the tcp/kube operations are allowed or not
type EvKubPolicy struct {
	Enabled bool `json:"enabled"` // allow access to kubernetes api
}

// EvjwtAlgo - jwt algorithm
// JWT token for edgeview
// JWT has 3 portion of items separated by '.' using base64url without padding,
// the 1st part is the algorithm, the 2nd is the info, the third is signing data
// the 1st and 2nd parts are from json format
type EvjwtAlgo struct {
	Alg string `json:"alg"` // algorithm, use 'ES256' or SHA256withECDSA
	Typ string `json:"typ"` // type, is 'JWT' string
}

// EvAuthType - enum for authentication type of edge-view
type EvAuthType int32

// EvAuthType defines the authentication types for edge-view.
const (
	EvAuthTypeUnspecified    EvAuthType = iota // EvAuthTypeUnspecified - an unspecified authentication type.
	EvAuthTypeControllerCert                   // EvAuthTypeControllerCert - using authen of controller cert
	EvAuthTypeSSHRsaKeys                       // EvAuthTypeSSHRsaKeys - using ssh rsa keys
)

// EvjwtInfo - token embedded info
// the info specifies where is the dispatcher endpoint, the intended EVE
// device with UUID string, the token expiration time and authentication nonce
type EvjwtInfo struct {
	Dep string     `json:"dep"` // dispatcher end-point string e.g. ip:port
	Sub string     `json:"sub"` // jwt subject, the device UUID string
	Exp uint64     `json:"exp"` // expiration time for the token
	Key string     `json:"key"` // key or nonce for payload hmac authentication
	Num uint8      `json:"num"` // number of instances, default is 1
	Enc bool       `json:"enc"` // payload with encryption, default is authentication
	Aut EvAuthType `json:"aut"` // authentication type
}

// EdgeviewStatus - status advertised by edge-view
// Not sending 'CmdOption' for now since it is logged for each command
// we can add it when figure out repliablly uploading
type EdgeviewStatus struct {
	ExpireOn    uint64    // unix time expiration in seconds
	StartedOn   time.Time // edge-view process started on timestamp
	CmdCountDev uint32    // total edge-view dev related commands performed
	CmdCountApp uint32    // total edge-view app related commands performed
	CmdCountExt uint32    // total edge-view ext related commands performed
}

// Key is global for edgeview for now
func (status EdgeviewStatus) Key() string {
	return "global"
}
