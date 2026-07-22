// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import (
	"os"
	"strings"
	"testing"

	"github.com/lf-edge/eve/pkg/pillar/types"
	uuid "github.com/satori/go.uuid"
)

// TestCreateDomConfigInjectionExtraArgs verifies that a newline in a
// controller-supplied field (VmConfig.ExtraArgs) cannot inject extra QEMU
// directives: CreateDomConfig rejects it instead of rendering the smuggled
// [device] section.
func TestCreateDomConfigInjectionExtraArgs(t *testing.T) {
	id, err := uuid.NewV4()
	if err != nil {
		t.Fatalf("NewV4 failed: %v", err)
	}

	// Payload tries to close the append="..." line and add a vfio-pci device.
	payload := "console=hvc0\"\n\n[device \"injected\"]\n  driver = \"vfio-pci\"\n  host = \"00:1f.0\"\n"

	config := types.DomainConfig{
		UUIDandVersion: types.UUIDandVersion{UUID: id, Version: "1.0"},
		VmConfig: types.VmConfig{
			Kernel:    "/boot/kernel",
			ExtraArgs: payload,
			Memory:    1024 * 1024 * 10,
			VCpus:     2,
		},
	}

	conf, err := os.CreateTemp("/tmp", "config-injection")
	if err != nil {
		t.Fatalf("Can't create config file: %v", err)
	}
	defer os.Remove(conf.Name())

	err = kvmIntel.CreateDomConfig(DefaultDomainName, config, types.DomainStatus{},
		nil, &types.AssignableAdapters{Initialized: true}, nil, "", conf)
	if err == nil {
		t.Fatalf("expected CreateDomConfig to reject the injected ExtraArgs, got nil")
	}

	result, readErr := os.ReadFile(conf.Name())
	if readErr != nil {
		t.Fatalf("reading conf file failed: %v", readErr)
	}
	if strings.Contains(string(result), "[device \"injected\"]") {
		t.Fatalf("injected section rendered despite rejection:\n%s", result)
	}
}
