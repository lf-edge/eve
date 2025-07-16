// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"fmt"
	"strings"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
)

// Requirement is a marker interface for all test requirements (e.g. device, hypervisor, filesystem).
type Requirement interface {
	isRequirement()
}

// Hypervisor identifies the hypervisor type required or detected on an EVE device.
type Hypervisor int

const (
	// HypervisorUndefined indicates no specific hypervisor is required or detected.
	HypervisorUndefined Hypervisor = iota
	// HypervisorKVM represents the KVM hypervisor.
	HypervisorKVM
	// HypervisorXen represents the Xen hypervisor.
	HypervisorXen
	// HypervisorKubevirt represents the KubeVirt hypervisor.
	HypervisorKubevirt
)

func (h Hypervisor) String() string {
	switch h {
	case HypervisorKVM:
		return "kvm"
	case HypervisorXen:
		return "xen"
	case HypervisorKubevirt:
		return "kubevirt"
	case HypervisorUndefined:
		fallthrough
	default:
		return "undefined"
	}
}

// FromString parses a hypervisor name string and sets the Hypervisor value.
func (h *Hypervisor) FromString(s string) error {
	switch strings.ToLower(s) {
	case "kvm":
		*h = HypervisorKVM
	case "xen":
		*h = HypervisorXen
	case "kubevirt":
		*h = HypervisorKubevirt
	case "", "undefined":
		*h = HypervisorUndefined
	default:
		return fmt.Errorf("invalid Hypervisor: %q", s)
	}
	return nil
}

// Filesystem identifies the filesystem type required or detected on an EVE device.
type Filesystem int

const (
	// FilesystemUndefined indicates no specific filesystem is required or detected.
	FilesystemUndefined Filesystem = iota
	// FilesystemEXT4 represents the ext4 filesystem.
	FilesystemEXT4
	// FilesystemZFS represents the ZFS filesystem.
	FilesystemZFS
)

// FromString parses a filesystem name string and sets the Filesystem value.
func (f *Filesystem) FromString(s string) error {
	switch strings.ToLower(s) {
	case "ext4":
		*f = FilesystemEXT4
	case "zfs":
		*f = FilesystemZFS
	case "", "undefined":
		*f = FilesystemUndefined
	default:
		return fmt.Errorf("invalid Filesystem: %q", s)
	}
	return nil
}

func (f Filesystem) String() string {
	switch f {
	case FilesystemEXT4:
		return "ext4"
	case FilesystemZFS:
		return "zfs"
	case FilesystemUndefined:
		fallthrough
	default:
		return "undefined"
	}
}

// ExistingEdgeDeviceReusePolicy defines how to reuse an existing EdgeDevice
// that already satisfies test requirements. Only one strategy can be selected.
// This helps control whether to reuse as-is, reset, or recreate the edge device
// before test execution.
type ExistingEdgeDeviceReusePolicy int

const (
	// UseAsIs : do nothing special, keep existing state.
	UseAsIs ExistingEdgeDeviceReusePolicy = iota
	// RebootEdgeDevice : just reboot edge device matching the requirements.
	RebootEdgeDevice
	// ResetDeviceConfig : reset the device configuration by clearing all
	// application-related settings while preserving the device network configuration.
	ResetDeviceConfig
	// ResetDeviceConfigAndReboot : combines ResetDeviceConfig with RebootEdgeDevice.
	ResetDeviceConfigAndReboot
	// ReonboardEdgeDevice forces re-onboarding of the device, even if it was previously
	// onboarded.
	// It removes the OnboardingStatus and edge device certificate, clears TPM, recreates
	// the device entry in the controller, resets device configuration (see ResetDeviceConfig)
	// and then reboots the device.
	ReonboardEdgeDevice
	// CreateFromScratchWithInstaller : re-create VM even if already exists using
	// EVE installer image.
	CreateFromScratchWithInstaller
	// CreateFromScratchWithLiveImage : re-create VM even if already exists using
	// EVE live image.
	CreateFromScratchWithLiveImage
)

// USBDevice identifies a USB device by vendor and product ID.
type USBDevice struct {
	VendorID  uint16
	ProductID uint16
}

// PCIDevice identifies a PCI device by vendor and device ID.
type PCIDevice struct {
	VendorID uint16
	DeviceID uint16
}

// RequireEdgeDevice : requirement to deploy single EVE device.
type RequireEdgeDevice struct {
	// Logical name used to reference the device within the evetest framework.
	Name string

	// Zero values mean that the test does not care about the particular resource size.
	// None of these will be ever created with zero count - not even ethernet interfaces.
	MinCPUs         uint8  // Default will be 4.
	MinRAMInMB      uint32 // Default will be 8192 MB.
	MinDiskSizeInMB uint32 // Default will be 28576 MB.

	WithEVEVersion string
	WithHypervisor Hypervisor
	WithTPM        bool

	WithFilesystem Filesystem
	// Mount the vault (or the entire persist partition when using ext4) with the
	// DIRSYNC flag, which makes all directory-entry updates synchronous.
	// This incurs significant I/O overhead in virtualized environments,
	// most noticeably during container image unpacking, so it is disabled by
	// default. Enable it only when the test explicitly exercises durability under
	// sudden failure conditions such as power loss or kernel crashes.
	WithDirSync bool

	// Configuration injected into the /config partition.
	WithSoftSerial              string
	WithGrubOptions             []string
	WithInjectedBootstrapConfig *EdgeDeviceConfig
	WithInjectedNetworkOverride *pillartypes.DevicePortConfig
	// framework automatically adds SSH key and enables console
	WithInjectedConfigProperties *pillartypes.ConfigItemValueMap

	// USB/PCI devices to passthrough into the edge device VM.
	WithUSBPassthrough []USBDevice // TODO
	WithPCIPassthrough []PCIDevice // TODO

	// What to do if EdgeDevice is already available (and still manageable)
	// from the previous test:
	DeviceReusePolicy ExistingEdgeDeviceReusePolicy
}

func (r RequireEdgeDevice) isRequirement() {}

// RequireNetworkModel : required Evetest-SDN network model.
type RequireNetworkModel struct {
	// NetworkModel.ControllerConfig is filled by the framework, do not set from the test.
	*api.NetworkModel
}

func (r RequireNetworkModel) isRequirement() {}

// RequireInternetConnectivity : requirement to provide IPv4/IPv6 Internet connectivity.
type RequireInternetConnectivity struct {
	RequireIPv6 bool
}

func (r RequireInternetConnectivity) isRequirement() {}
