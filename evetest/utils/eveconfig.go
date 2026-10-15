// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// MakeEVEConfigDir creates a temporary directory containing EVE configuration
// files derived from the provided EveConfig. Each non-empty field is written
// into a specific file under the directory structure expected by EVE's
// config.img overlay mechanism (see pkg/eve/runme.sh's "/in" handling:
// `mcopy -o -i /bits/config.img -s /in/* ::/`). The returned directory is
// meant to be bind-mounted at "/in" when running an EVE docker image action
// (installer_raw, live, installer_net, ...).
//
// Used by both the broker (building a device's local disk image) and evetest
// core (building network-boot artifacts), since both need to inject the same
// per-device onboarding cert/key, bootstrap config, grub options, etc. into
// the same config.img layout.
func MakeEVEConfigDir(parentDir string, config *api.EveConfig,
	proxyCACerts []*pem.Block, softSerial string) (dirPath string, err error) {

	if config == nil && len(proxyCACerts) == 0 && softSerial == "" {
		return "", nil
	}

	dirPath, err = os.MkdirTemp(parentDir, "eve-config-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary config directory: %w", err)
	}
	// Ensure cleanup on error
	defer func() {
		if err != nil {
			_ = os.RemoveAll(dirPath)
		}
	}()

	// Helper to write a file only if data is non-empty
	writeFile := func(relPath string, data []byte) error {
		if len(data) == 0 {
			return nil
		}
		fullPath := filepath.Join(dirPath, relPath)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return fmt.Errorf("failed to create directory for %q: %w", fullPath, err)
		}
		if err := os.WriteFile(fullPath, data, 0o600); err != nil {
			return fmt.Errorf("failed to write file %q: %w", fullPath, err)
		}
		return nil
	}

	err = writeFile("soft_serial", []byte(softSerial))
	if err != nil {
		return "", err
	}
	err = writeFile("server", []byte(config.GetServerName()))
	if err != nil {
		return "", err
	}

	if len(config.GetOnboardCertPem()) > 0 {
		_, err = ValidatePEMCerts([]byte(config.GetOnboardCertPem()), true)
		if err != nil {
			return "", fmt.Errorf("onboard certificate invalid: %w", err)
		}
		err = writeFile("onboard.cert.pem", []byte(config.GetOnboardCertPem()))
		if err != nil {
			return "", err
		}
	}
	if len(config.GetOnboardKeyPem()) > 0 {
		err = ValidatePEMPrivateKeyECDSA([]byte(config.GetOnboardKeyPem()))
		if err != nil {
			return "", fmt.Errorf("onboard key invalid: %w", err)
		}
		err = writeFile("onboard.key.pem", []byte(config.GetOnboardKeyPem()))
		if err != nil {
			return "", err
		}
	}

	if len(config.GetRootCertPem()) > 0 {
		_, err = ValidatePEMCerts([]byte(config.GetRootCertPem()), true)
		if err != nil {
			return "", fmt.Errorf("root certificate invalid: %w", err)
		}
		err = writeFile("root-certificate.pem", []byte(config.GetRootCertPem()))
		if err != nil {
			return "", err
		}
	}

	// Handle V2 TLS certs and append proxy CA certs
	var certDataBuilder strings.Builder
	writeV2TLS := false

	// Validate and append V2TlsCertsPem
	for _, pemStr := range config.GetV2TlsCertsPem() {
		_, err = ValidatePEMCerts([]byte(pemStr), true)
		if err != nil {
			return "", fmt.Errorf("v2 TLS certificate invalid: %w", err)
		}
		certDataBuilder.WriteString(pemStr)
		if !strings.HasSuffix(pemStr, "\n") {
			certDataBuilder.WriteString("\n")
		}
		writeV2TLS = true
	}

	// Append validated proxy CA certificates
	for _, block := range proxyCACerts {
		writeV2TLS = true
		certPEM := pem.EncodeToMemory(block)
		certDataBuilder.Write(certPEM)
		if len(certPEM) > 0 && certPEM[len(certPEM)-1] != '\n' {
			certDataBuilder.WriteString("\n")
		}
	}

	if writeV2TLS {
		certData := []byte(certDataBuilder.String())
		err = writeFile("v2tlsbaseroot-certificates.pem", certData)
		if err != nil {
			return "", err
		}
	}

	if len(config.GetSshKeys()) > 0 {
		keysData := strings.Join(config.GetSshKeys(), "\n")
		err = writeFile("authorized_keys", []byte(keysData))
		if err != nil {
			return "", err
		}
	}

	if len(config.GetGrubOptions()) > 0 {
		grubConfig := strings.Join(config.GetGrubOptions(), "\n")
		err = writeFile("grub.cfg", []byte(grubConfig))
		if err != nil {
			return "", err
		}
	}

	err = writeFile("GlobalConfig/global.json", []byte(config.GetGlobalJson()))
	if err != nil {
		return "", err
	}
	err = writeFile("DevicePortConfig/override.json", []byte(config.GetOverrideJson()))
	if err != nil {
		return "", err
	}
	if len(config.GetBootstrapConfigPb()) > 0 {
		err = writeFile("bootstrap-config.pb", config.GetBootstrapConfigPb())
		if err != nil {
			return "", err
		}
	}

	return dirPath, nil
}
