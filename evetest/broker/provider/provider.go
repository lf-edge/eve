// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"io"
	"net"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
)

// DeviceProvider is an interface for provisioning and managing compute nodes.
// A "device" represents a compute node, typically a VM provided by a hypervisor
// (libvirt, Proxmox), but can also represent physical hardware from a device pool.
// The interface is exported to allow external packages to provide custom implementations.
type DeviceProvider interface {
	// GetSupportedDeviceArchs returns a list of CPU architectures supported by
	// this device provider (and the host it is running on in case of virtualization).
	GetSupportedDeviceArchs() ([]api.ArchType, error)

	// SetupDevice creates a new device in a powered-off state with the specified configuration.
	// The device must be created but not started, allowing for additional configuration
	// before power-on if needed.
	//
	// Parameters:
	//   - name: Unique identifier for the device (must be unique within the provider's scope)
	//   - spec: Device specification including compute, storage, and network configuration
	//
	// Returns an error if:
	//   - A device with the same name already exists
	//   - The specification is invalid
	//   - Resource allocation fails
	SetupDevice(ctx context.Context, name string, spec DeviceSpec) error

	// TeardownDevice stops the device (if running) and removes the device definition
	// from the provider (e.g. undefines the libvirt domain). It also removes any
	// provider-managed side-files such as NVRAM (OVMF_VARS.fd) and unused virtual
	// networks. It does NOT delete the disk image files referenced in DeviceSpec.Disks;
	// disk cleanup is the caller's responsibility.
	TeardownDevice(ctx context.Context, name string) error

	// PowerOnDevice starts a previously created device.
	// Returns an error if the device doesn't exist or is already running.
	PowerOnDevice(ctx context.Context, name string) error

	// PowerOffDevice performs a hard power-off of the device (equivalent to pulling the power plug).
	// For a graceful shutdown, use ShutdownDevice instead.
	// Returns an error if the device doesn't exist or is already powered off.
	PowerOffDevice(ctx context.Context, name string) error

	// ShutdownDevice performs a graceful shutdown of the device.
	// This sends an ACPI shutdown signal, allowing the guest OS to shut down cleanly.
	// Unlike PowerOffDevice, this waits for the guest to respond.
	// Returns an error if the device doesn't exist or is already powered off.
	ShutdownDevice(ctx context.Context, name string) error

	// RebootDevice performs a hard reboot of the device.
	// Returns an error if the device doesn't exist.
	RebootDevice(ctx context.Context, name string) error

	// GetDeviceConsoleOutput retrieves the console output (serial console) of the device.
	// Returns the console output as a string, or an error if unavailable.
	GetDeviceConsoleOutput(ctx context.Context, name string) (string, error)

	// AttachToDeviceConsole returns a stream attached to the device's serial console.
	//
	// The `echoed` return value indicates whether input sent to the stream will be echoed
	// back by the device. If used interactively (e.g., connected to a terminal), the
	// caller should disable local terminal echo and enable raw mode to avoid duplicate
	// characters being displayed.
	//
	// The `telnet` return value indicates whether the stream uses the telnet protocol
	// for console communication.
	//
	// The caller is responsible for closing the returned stream when finished.
	AttachToDeviceConsole(ctx context.Context,
		name string) (stream io.ReadWriteCloser, echoed, telnet bool, err error)

	// GetDeviceStatus returns the current status of the specified device.
	// Returns an error if the device doesn't exist.
	GetDeviceStatus(ctx context.Context, name string) (DeviceStatus, error)

	// GetDeviceUplinkIPs returns all IP addresses assigned to the uplink interfaces.
	GetDeviceUplinkIPs(ctx context.Context, devName string) ([]net.IP, error)

	// WatchDeviceStatus watches for status changes of the specified device.
	// Returns a channel that will receive status updates whenever the device state changes.
	// The channel is closed when the context is cancelled or an unrecoverable error occurs.
	// The first value sent on the channel is always the current status.
	WatchDeviceStatus(ctx context.Context, name string) <-chan DeviceStatus

	// ListDevices returns the names of all created devices.
	ListDevices(ctx context.Context) ([]string, error)

	// TeardownAll removes all VMs, networks, etc., created by the provider.
	TeardownAll(ctx context.Context) error

	// ReconfigureDeviceDisks updates the disk list of a stopped device in place,
	// without tearing it down and recreating it. All other device state (TPM,
	// UEFI NVRAM, console port, network interfaces) is preserved.
	//
	// Intended for the EVE installer two-step flow: after the installer VM has
	// finished writing EVE to disk, call this to drop the installer image from
	// the disk list so the next PowerOnDevice boots directly into EVE.
	//
	// The device must be set up and powered off when this is called.
	ReconfigureDeviceDisks(ctx context.Context, name string, newDisks []DiskImage) error

	// Close releases all resources associated with the provider connection.
	Close() error
}

// DiskImageFormat is the on-disk format of a disk image file.
type DiskImageFormat int32

const (
	// DiskImageFormatQcow2 is the QCOW2 disk image format.
	DiskImageFormatQcow2 DiskImageFormat = iota
	// DiskImageFormatRaw is the raw disk image format.
	DiskImageFormatRaw
)

// DiskImage describes a single disk to attach to a device.
type DiskImage struct {
	// Format is the on-disk format of the image file.
	Format DiskImageFormat
	// Path is the filesystem path to the image file.
	// The file must already exist when SetupDevice is called.
	Path string
}

// DeviceSpec defines the configuration for a compute device.
type DeviceSpec struct {
	// Disks is an ordered list of disk images to attach to the device, in boot order.
	Disks []DiskImage

	// UEFIFirmwareDirPath is the path to a directory containing UEFI firmware
	// binaries (OVMF_CODE.fd, OVMF_VARS.fd). Leave empty to omit UEFI.
	UEFIFirmwareDirPath string

	// CPU architecture.
	Arch api.ArchType

	// CPUs is the number of CPU cores to allocate.
	CPUs uint

	// MemoryBytes is the amount of RAM in bytes.
	MemoryBytes uint64

	// Enable attachment of a TPM device (Trusted Platform Module).
	WithTPM bool

	// SerialNumber is the system serial number exposed to the guest firmware
	// and operating system (DMI/SMBIOS System Serial Number).
	SerialNumber string

	// NetworkInterfaces defines the network configuration for the device.
	NetworkInterfaces []NetworkInterfaceSpec
}

// NetworkInterfaceSpec defines a single network interface for a device.
type NetworkInterfaceSpec struct {
	// Name is a unique identifier for this interface within the device.
	// This is used to reference the interface inside NetworkPeer.
	Name string

	// MACAddress is the MAC address for this interface.
	// If empty, the provider should generate a random MAC address.
	// Format: "00:11:22:33:44:55"
	MACAddress net.HardwareAddr

	// Connection defines how this interface connects to the network.
	Connection ConnectionSpec
}

// ConnectionSpec defines the type of connection for an interface.
// This is a one-of type: exactly one of Uplink or XConnect must be non-nil.
//
// An interface can either:
//   - Connect to an uplink (host network with potential Internet access), or
//   - Connect directly to another device's interface (point-to-point link)
type ConnectionSpec struct {
	// Uplink specifies connection to the host network with optional port forwarding.
	// If non-nil, XConnect must be nil.
	Uplink *UplinkSpec

	// XConnect specifies a direct connection to another device's interface.
	// If non-nil, Uplink must be nil.
	XConnect *XConnectSpec
}

// UplinkSpec defines connection to the host network.
type UplinkSpec struct {
	// EnableIPv6 is used to enable IPv6 (additionally to IPv4) on the uplink interface
	// (if available).
	EnableIPv6 bool
}

// XConnectSpec defines a direct cross-connect to another device's interface.
// This creates an isolated point-to-point link with no DHCP or routing,
// just a simple L2 connection between two devices.
type XConnectSpec struct {
	// PeerDeviceName is the name of the device to connect to.
	PeerDeviceName string

	// PeerInterfaceName is the name of the interface on the peer device.
	PeerInterfaceName string
}

// TransportProtocol specifies the transport-layer protocol
// for the forwarding rule (e.g., TCP or UDP).
type TransportProtocol string

const (
	// TransportProtocolTCP is the TCP transport protocol identifier.
	TransportProtocolTCP TransportProtocol = "tcp"
	// TransportProtocolUDP is the UDP transport protocol identifier.
	TransportProtocolUDP TransportProtocol = "udp"
)

// DeviceStatus represents the current power/lifecycle state of a device.
type DeviceStatus string

const (
	// DeviceStatusRunning indicates the device is powered on and running.
	DeviceStatusRunning DeviceStatus = "running"

	// DeviceStatusStopped indicates the device is powered off.
	DeviceStatusStopped DeviceStatus = "stopped"

	// DeviceStatusSuspended indicates the device is suspended/paused.
	DeviceStatusSuspended DeviceStatus = "suspended"

	// DeviceStatusCrashed indicates the device is in a crashed state.
	DeviceStatusCrashed DeviceStatus = "crashed"

	// DeviceStatusUnknown indicates the device state cannot be determined.
	DeviceStatusUnknown DeviceStatus = "unknown"
)
