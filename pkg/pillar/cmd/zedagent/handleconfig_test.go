// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedagent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/onsi/gomega"
	"google.golang.org/protobuf/proto"

	zauth "github.com/lf-edge/eve-api/go/auth"
	zcert "github.com/lf-edge/eve-api/go/certs"
	zconfig "github.com/lf-edge/eve-api/go/config"
	zcommon "github.com/lf-edge/eve-api/go/evecommon"
	"github.com/lf-edge/eve/pkg/pillar/types"
)

// testCerts holds a self-signed CA and a signing leaf cert/key for use in tests.
type testCerts struct {
	rootCertPEM    []byte
	signingCertPEM []byte
	signingKey     *ecdsa.PrivateKey
}

// generateTestCerts creates an ECDSA P-256 root CA and a signing leaf cert
// signed by that CA.
func generateTestCerts(t *testing.T) testCerts {
	t.Helper()

	// Root CA key and self-signed cert.
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	rootCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	// Signing leaf key and cert signed by root CA.
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signingTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Signing Cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	signingDER, err := x509.CreateCertificate(rand.Reader, signingTmpl, rootCert, &signingKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create signing cert: %v", err)
	}
	signingCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signingDER})

	return testCerts{
		rootCertPEM:    rootCertPEM,
		signingCertPEM: signingCertPEM,
		signingKey:     signingKey,
	}
}

// buildBootstrapConfigBytes constructs a signed BootstrapConfig proto wrapping
// the given EdgeDevConfig, using the provided signing key and cert.
func buildBootstrapConfigBytes(t *testing.T, tc testCerts, devConfig *zconfig.EdgeDevConfig) []byte {
	t.Helper()

	payload, err := proto.Marshal(devConfig)
	if err != nil {
		t.Fatalf("marshal EdgeDevConfig: %v", err)
	}

	// Sign SHA256(payload) with the signing key.  The verifier expects r||s
	// with each component zero-padded to 32 bytes (P-256 key size).
	h := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, tc.signingKey, h[:])
	if err != nil {
		t.Fatalf("ecdsa.Sign: %v", err)
	}
	sigBytes := make([]byte, 64)
	r.FillBytes(sigBytes[:32])
	s.FillBytes(sigBytes[32:])

	// SenderCertHash = SHA256 of the signing cert PEM bytes.
	certHash := sha256.Sum256(tc.signingCertPEM)

	authContainer := &zauth.AuthContainer{
		ProtectedPayload: &zauth.AuthBody{Payload: payload},
		Algo:             zcommon.HashAlgorithm_HASH_ALGORITHM_SHA256_32BYTES,
		SenderCertHash:   certHash[:],
		SignatureHash:    sigBytes,
	}

	bootstrapCfg := &zconfig.BootstrapConfig{
		SignedConfig: authContainer,
		ControllerCerts: []*zcert.ZCert{
			{
				Type: zcert.ZCertType_CERT_TYPE_CONTROLLER_SIGNING,
				Cert: tc.signingCertPEM,
			},
		},
	}
	bs, err := proto.Marshal(bootstrapCfg)
	if err != nil {
		t.Fatalf("marshal BootstrapConfig: %v", err)
	}
	return bs
}

// ---- validateBootstrapConfig tests ----

func TestValidateBootstrapConfigMissingFile(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	initGetConfigCtx(g) // initialises package-level log/logger

	dir := t.TempDir()
	devCfg, err := validateBootstrapConfig(
		filepath.Join(dir, "bootstrap-config.pb"),
		filepath.Join(dir, "root-certificate.pem"),
	)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(devCfg).To(gomega.BeNil())
}

func TestValidateBootstrapConfigSuccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	initGetConfigCtx(g)

	tc := generateTestCerts(t)
	dir := t.TempDir()

	rootCertFile := filepath.Join(dir, "root-certificate.pem")
	bootstrapFile := filepath.Join(dir, "bootstrap-config.pb")

	g.Expect(os.WriteFile(rootCertFile, tc.rootCertPEM, 0644)).To(gomega.Succeed())

	// Use a non-default field so proto.Marshal produces non-empty bytes;
	// proto3 omits empty byte slices on the wire, making GetPayload() return nil.
	devConfig := &zconfig.EdgeDevConfig{
		Id: &zconfig.UUIDandVersion{
			Uuid:    "12345678-1234-1234-1234-123456789012",
			Version: "1",
		},
	}
	g.Expect(os.WriteFile(bootstrapFile,
		buildBootstrapConfigBytes(t, tc, devConfig), 0644)).To(gomega.Succeed())

	devCfg, err := validateBootstrapConfig(bootstrapFile, rootCertFile)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(devCfg).NotTo(gomega.BeNil())
	g.Expect(devCfg.GetId().GetUuid()).To(gomega.Equal("12345678-1234-1234-1234-123456789012"))
}

func TestValidateBootstrapConfigMalformedProto(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	initGetConfigCtx(g)

	dir := t.TempDir()
	rootCertFile := filepath.Join(dir, "root-certificate.pem")
	bootstrapFile := filepath.Join(dir, "bootstrap-config.pb")

	tc := generateTestCerts(t)
	g.Expect(os.WriteFile(rootCertFile, tc.rootCertPEM, 0644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(bootstrapFile, []byte("not a valid protobuf"), 0644)).To(gomega.Succeed())

	devCfg, err := validateBootstrapConfig(bootstrapFile, rootCertFile)
	g.Expect(err).NotTo(gomega.BeNil())
	g.Expect(devCfg).To(gomega.BeNil())
}

func TestValidateBootstrapConfigInvalidCertChain(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	initGetConfigCtx(g)

	// Two independent CAs: bootstrap config signed under tc1, but root cert file
	// contains tc2's root — chain verification must fail.
	tc1 := generateTestCerts(t)
	tc2 := generateTestCerts(t)
	dir := t.TempDir()

	rootCertFile := filepath.Join(dir, "root-certificate.pem")
	bootstrapFile := filepath.Join(dir, "bootstrap-config.pb")

	g.Expect(os.WriteFile(rootCertFile, tc2.rootCertPEM, 0644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(bootstrapFile,
		buildBootstrapConfigBytes(t, tc1, &zconfig.EdgeDevConfig{}), 0644)).To(gomega.Succeed())

	devCfg, err := validateBootstrapConfig(bootstrapFile, rootCertFile)
	g.Expect(err).NotTo(gomega.BeNil())
	g.Expect(devCfg).To(gomega.BeNil())
}

func TestValidateBootstrapConfigInvalidSignature(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	initGetConfigCtx(g)

	tc := generateTestCerts(t)
	dir := t.TempDir()

	rootCertFile := filepath.Join(dir, "root-certificate.pem")
	bootstrapFile := filepath.Join(dir, "bootstrap-config.pb")

	g.Expect(os.WriteFile(rootCertFile, tc.rootCertPEM, 0644)).To(gomega.Succeed())

	// Build a valid bootstrap config then corrupt its signature.
	devConfig := &zconfig.EdgeDevConfig{Id: &zconfig.UUIDandVersion{Uuid: "test", Version: "1"}}
	bs := buildBootstrapConfigBytes(t, tc, devConfig)
	parsed := &zconfig.BootstrapConfig{}
	g.Expect(proto.Unmarshal(bs, parsed)).To(gomega.Succeed())
	parsed.SignedConfig.SignatureHash[0] ^= 0xff // flip bits
	corrupted, err := proto.Marshal(parsed)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(os.WriteFile(bootstrapFile, corrupted, 0644)).To(gomega.Succeed())

	devCfg, err := validateBootstrapConfig(bootstrapFile, rootCertFile)
	g.Expect(err).NotTo(gomega.BeNil())
	g.Expect(devCfg).To(gomega.BeNil())
}

// TestBootstrapConfigPublishesDPC verifies that a bootstrap config carrying a
// system adapter results in a DevicePortConfig being published with origin set
// to NetworkConfigOriginBootstrap and the expected port details.
func TestBootstrapConfigPublishesDPC(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	tc := generateTestCerts(t)
	dir := t.TempDir()

	rootCertFile := filepath.Join(dir, "root-certificate.pem")
	bootstrapFile := filepath.Join(dir, "bootstrap-config.pb")
	g.Expect(os.WriteFile(rootCertFile, tc.rootCertPEM, 0644)).To(gomega.Succeed())

	networkUUID := "572cd3bc-ade6-42ad-97a0-22cd24fed1a0"
	devConfig := &zconfig.EdgeDevConfig{
		Id: &zconfig.UUIDandVersion{Uuid: "bootstrap-test-device", Version: "1"},
		Networks: []*zconfig.NetworkConfig{
			{
				Id:   networkUUID,
				Type: zcommon.NetworkType_V4,
				Ip:   &zcommon.Ipspec{Dhcp: zcommon.DHCPType_Client},
			},
		},
		DeviceIoList: []*zconfig.PhysicalIO{
			{
				Ptype:        zcommon.PhyIoType_PhyIoNetEth,
				Phylabel:     "ethernet0",
				Logicallabel: "uplink",
				Assigngrp:    "eth-grp-1",
				Phyaddrs:     map[string]string{"ifname": "eth0"},
				Usage:        zcommon.PhyIoMemberUsage_PhyIoUsageMgmtAndApps,
			},
		},
		SystemAdapterList: []*zconfig.SystemAdapter{
			{
				Name:           "mgmt0",
				Uplink:         true,
				NetworkUUID:    networkUUID,
				LowerLayerName: "uplink",
			},
		},
	}
	g.Expect(os.WriteFile(bootstrapFile,
		buildBootstrapConfigBytes(t, tc, devConfig), 0644)).To(gomega.Succeed())

	// Validate and retrieve the parsed config through the full crypto path.
	parsedCfg, err := validateBootstrapConfig(bootstrapFile, rootCertFile)
	g.Expect(err).To(gomega.BeNil())
	g.Expect(parsedCfg).NotTo(gomega.BeNil())

	// Apply the PhysicalIO list so parseSystemAdapterConfig can resolve port names.
	parseDeviceIoListConfig(ctx, parsedCfg)
	parseNetworkXObjectConfig(ctx, parsedCfg)
	parseSystemAdapterConfig(ctx, parsedCfg, fromBootstrap, true)

	portCfgItem, err := ctx.pubDevicePortConfig.Get("zedagent")
	g.Expect(err).To(gomega.BeNil())
	dpc := portCfgItem.(types.DevicePortConfig)
	g.Expect(dpc.Ports).To(gomega.HaveLen(1))
	port := dpc.Ports[0]
	g.Expect(port.Logicallabel).To(gomega.Equal("mgmt0"))
	g.Expect(port.IfName).To(gomega.Equal("eth0"))
	g.Expect(port.ConfigSource.Origin).To(gomega.Equal(types.NetworkConfigOriginBootstrap))
}

// ---- loadGlobalConfigImpl tests ----

func TestLoadGlobalConfigMissingFile(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	result := loadGlobalConfigImpl(ctx,
		filepath.Join(dir, "global.json"),
		filepath.Join(dir, "authorized_keys"))
	g.Expect(result).To(gomega.BeFalse())
}

func TestLoadGlobalConfigSuccess(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()

	// Write a GlobalConfig JSON that sets a recognisable value.
	cfg := types.DefaultConfigItemValueMap()
	cfg.SetGlobalValueInt(types.ConfigInterval, 42)
	data, err := json.Marshal(cfg)
	g.Expect(err).To(gomega.BeNil())

	globalFile := filepath.Join(dir, "global.json")
	g.Expect(os.WriteFile(globalFile, data, 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, filepath.Join(dir, "no_keys"))
	g.Expect(result).To(gomega.BeTrue())
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueInt(types.ConfigInterval)).
		To(gomega.Equal(uint32(42)))
}

func TestLoadGlobalConfigWithAuthorizedKeys(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()

	cfg := types.DefaultConfigItemValueMap()
	data, err := json.Marshal(cfg)
	g.Expect(err).To(gomega.BeNil())

	globalFile := filepath.Join(dir, "global.json")
	authKeysFile := filepath.Join(dir, "authorized_keys")
	const sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKey test@example.com"
	g.Expect(os.WriteFile(globalFile, data, 0644)).To(gomega.Succeed())
	g.Expect(os.WriteFile(authKeysFile, []byte(sshKey+"\n"), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, authKeysFile)
	g.Expect(result).To(gomega.BeTrue())
	g.Expect(ctx.zedagentCtx.globalConfig.GlobalValueString(types.SSHAuthorizedKeys)).
		To(gomega.Equal(sshKey))
}

func TestLoadGlobalConfigMalformedJSON(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	ctx := initGetConfigCtx(g)

	dir := t.TempDir()
	globalFile := filepath.Join(dir, "global.json")
	g.Expect(os.WriteFile(globalFile, []byte("{not valid json}"), 0644)).To(gomega.Succeed())

	result := loadGlobalConfigImpl(ctx, globalFile, filepath.Join(dir, "no_keys"))
	g.Expect(result).To(gomega.BeFalse())
}
