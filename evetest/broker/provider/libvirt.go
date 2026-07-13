// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build cgo

package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"libvirt.org/go/libvirt"
	"libvirt.org/go/libvirtxml"
)

// LibvirtProvider manages the lifecycle of VMs and networks using libvirt.
// It creates domains with a fixed prefix (see namePrefix) and networks with a
// fixed, shorter prefix (see networkPrefix), and provides methods for setup,
// teardown, status watching, and cleanup.
type LibvirtProvider struct {
	conf  LibvirtProviderConf
	conn  *libvirt.Connect
	mutex sync.Mutex

	// watchers holds all registered watchers for domain lifecycle events.
	// The key is domain name (without prefix), and the value is a slice
	// of channels that receive DeviceStatus updates.
	watchers map[string][]chan DeviceStatus
}

// LibvirtProviderConf : configuration for the libvirt provider.
type LibvirtProviderConf struct {
	CommonProviderConf
}

// NewLibvirtProvider connects to the local libvirt instance.
// Remote libvirt hosts are not supported.
func NewLibvirtProvider(conf LibvirtProviderConf) (*LibvirtProvider, error) {
	// Initialize the default libvirt event loop
	libvirt.EventRegisterDefaultImpl()
	go func() {
		for {
			libvirt.EventRunDefaultImpl()
		}
	}()

	conn, err := libvirt.NewConnect("qemu:///system")
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}

	p := &LibvirtProvider{
		conf:     conf,
		conn:     conn,
		watchers: make(map[string][]chan DeviceStatus),
	}

	// Register lifecycle events for all domains
	_, err = conn.DomainEventLifecycleRegister(nil, p.domainLifecycleCallback)
	if err != nil {
		return nil, fmt.Errorf("failed to register libvirt domain lifecycle event: %w", err)
	}

	return p, nil
}

// -------- DeviceProvider implementation --------

// Close closes the libvirt connection.
func (p *LibvirtProvider) Close() error {
	if p.conn == nil {
		return nil
	}
	_, err := p.conn.Close()
	return err
}

// GetSupportedDeviceArchs returns the list of CPU architectures supported by the
// libvirt host (without emulation, which we want to avoid). It queries libvirt
// capabilities XML and extracts the host's native CPU architecture. If capabilities
// cannot be retrieved, it falls back to the local runtime architecture.
func (p *LibvirtProvider) GetSupportedDeviceArchs() ([]api.ArchType, error) {
	capsXML, err := p.conn.GetCapabilities()
	if err != nil {
		// Fallback to runtime architecture if libvirt query fails
		return archFromRuntime()
	}

	var caps libvirtxml.Caps
	if err := caps.Unmarshal(capsXML); err != nil {
		// Fallback to runtime architecture if Unmarshal fails
		return archFromRuntime()
	}

	hostArch := caps.Host.CPU.Arch
	switch hostArch {
	case "x86_64":
		return []api.ArchType{api.ArchType_ARCH_AMD64}, nil
	case "aarch64":
		return []api.ArchType{api.ArchType_ARCH_ARM64}, nil
	default:
		return nil, fmt.Errorf("unrecognized host architecture reported by libvirt: %s",
			hostArch)
	}
}

// Capabilities returns the full capability set: the libvirt provider runs on the
// local host and applies the host-level tweaks required to forward link-local
// L2 protocols, and supports emulated TPM.
func (p *LibvirtProvider) Capabilities() []api.Capability {
	return fullCapabilitySet()
}

// SetupDevice creates a VM in a powered-off state.
func (p *LibvirtProvider) SetupDevice(
	ctx context.Context, name string, spec DeviceSpec) error {
	log := logger.FromContext(ctx)

	// Network definition
	var interfaces []libvirtxml.DomainInterface
	for _, iface := range spec.NetworkInterfaces {
		var netName string
		switch {
		case iface.Connection.Uplink != nil:
			netName = uplinkNetwork
			if err := p.ensureUplinkNetwork(log); err != nil {
				return err
			}

		case iface.Connection.XConnect != nil:
			xconnect := iface.Connection.XConnect
			netName = xconnectNetworkName(
				name, iface.Name, xconnect.PeerDeviceName, xconnect.PeerInterfaceName)
			if err := p.ensureXConnectNetwork(log, netName); err != nil {
				return err
			}

		default:
			err := fmt.Errorf("missing ConnectionSpec for interface %q in device %q",
				iface.Name, name)
			log.Error(err)
			return err
		}

		ifaceXML := libvirtxml.DomainInterface{
			Alias: &libvirtxml.DomainAlias{
				Name: iface.Name,
			},
			Source: &libvirtxml.DomainInterfaceSource{
				Network: &libvirtxml.DomainInterfaceSourceNetwork{
					Network: netName,
				},
			},
			MAC: &libvirtxml.DomainInterfaceMAC{
				Address: iface.MACAddress.String(),
			},
			Model: &libvirtxml.DomainInterfaceModel{
				Type: "virtio",
			},
		}
		interfaces = append(interfaces, ifaceXML)
	}

	// Disk definitions. Optionally configure UEFI firmware if
	// UEFIFirmwareDirPath is set on the device spec.
	var disks []libvirtxml.DomainDisk

	if len(spec.Disks) == 0 {
		err := fmt.Errorf("no disk images specified for device %q", name)
		log.Error(err)
		return err
	}
	for i, disk := range spec.Disks {
		diskType := "qcow2"
		if disk.Format == DiskImageFormatRaw {
			diskType = "raw"
		}
		absPath, err := utils.ResolveFile(disk.Path)
		if err != nil {
			err = fmt.Errorf("failed to resolve disk path %q: %w", disk.Path, err)
			log.Error(err)
			return err
		}
		disks = append(disks, libvirtxml.DomainDisk{
			Device: "disk",
			Driver: &libvirtxml.DomainDiskDriver{
				Name: "qemu",
				Type: diskType,
			},
			Source: &libvirtxml.DomainDiskSource{
				File: &libvirtxml.DomainDiskSourceFile{
					File: absPath,
				},
			},
			Target: &libvirtxml.DomainDiskTarget{
				Dev: fmt.Sprintf("vd%c", rune('a'+i)),
				Bus: "virtio",
			},
		})
	}

	// Console definition
	consoleLogFile := p.getDeviceConsoleLogFile(name)
	// Pre-create console log file so that libvirt doesn't create it as root.
	if err := os.MkdirAll(filepath.Dir(consoleLogFile), 0o755); err != nil {
		return fmt.Errorf("failed to create console log directory: %w", err)
	}
	if _, err := os.Stat(consoleLogFile); os.IsNotExist(err) {
		// Create the file and set appropriate permissions.
		file, err := os.OpenFile(consoleLogFile, os.O_CREATE|os.O_WRONLY, 0o660)
		if err != nil {
			return fmt.Errorf("failed to pre-create console log file %q: %w",
				consoleLogFile, err)
		}
		file.Close()
	}
	port := uint(0) // first serial port
	hostIP, err := p.getLibvirtHostIP()
	if err != nil {
		log.Error(err)
		return err
	}
	consolePort, err := utils.FindUnusedPort(hostIP)
	if err != nil {
		log.Error(err)
		return err
	}
	console := libvirtxml.DomainConsole{
		Target: &libvirtxml.DomainConsoleTarget{
			Type: "serial",
			Port: &port,
		},
		Source: &libvirtxml.DomainChardevSource{
			TCP: &libvirtxml.DomainChardevSourceTCP{
				Mode:    "bind",
				Host:    "0.0.0.0",
				Service: strconv.Itoa(int(consolePort)),
			},
		},
		Log: &libvirtxml.DomainChardevLog{
			File:   consoleLogFile,
			Append: "on",
		},
		Protocol: &libvirtxml.DomainChardevProtocol{
			Type: "telnet",
		},
	}

	// Domain XML
	memKiB := uint(spec.MemoryBytes >> 10)

	// Build the Domain.OS with optional loader/nvram if UEFI dir was provided.
	domainOS := &libvirtxml.DomainOS{
		Type: &libvirtxml.DomainOSType{
			Arch:    detectLibvirtArch(),
			Machine: "q35",
			Type:    "hvm",
		},
		BootDevices: []libvirtxml.DomainBootDevice{
			{Dev: "hd"},
		},
	}

	// Unlike QEMU run directly (where ACPI is enabled by default), libvirt
	// disables ACPI unless it is explicitly requested. Without ACPI, a q35
	// guest cannot bring PCIe devices behind root ports out of the D3cold
	// power state ("can't change power state from D3cold to D0"), leaving
	// e.g. virtio NICs of the BIOS-booted SDN VM undetected.
	features := &libvirtxml.DomainFeatureList{
		ACPI: &libvirtxml.DomainFeature{},
		APIC: &libvirtxml.DomainFeatureAPIC{},
	}

	// If UEFI firmware was configured, attach loader + nvram.
	if spec.UEFIFirmwareDirPath != "" {
		codePath := filepath.Join(spec.UEFIFirmwareDirPath, "OVMF_CODE.fd")
		varsPath := filepath.Join(spec.UEFIFirmwareDirPath, "OVMF_VARS.fd")

		codePath, err = utils.ResolveFile(codePath)
		if err != nil {
			err = fmt.Errorf("failed to resolve OVMF_CODE.fd: %w", err)
			log.Error(err)
			return err
		}
		varsPath, err = utils.ResolveFile(varsPath)
		if err != nil {
			err = fmt.Errorf("failed to resolve OVMF_VARS.fd: %w", err)
			log.Error(err)
			return err
		}

		domainOS.Loader = &libvirtxml.DomainLoader{
			Path:     codePath,
			Readonly: "yes",
			Type:     "pflash",
		}
		domainOS.NVRam = &libvirtxml.DomainNVRam{
			NVRam: varsPath,
		}
	}

	// Define serial number inside the system info.
	var sysInfos []libvirtxml.DomainSysInfo
	if spec.SerialNumber != "" {
		domainOS.SMBios = &libvirtxml.DomainSMBios{
			Mode: "sysinfo",
		}
		sysInfos = append(sysInfos, libvirtxml.DomainSysInfo{
			SMBIOS: &libvirtxml.DomainSysInfoSMBIOS{
				System: &libvirtxml.DomainSysInfoSystem{
					Entry: []libvirtxml.DomainSysInfoEntry{
						{
							Name:  "serial",
							Value: spec.SerialNumber,
						},
					},
				},
			},
		})
	}

	// Define devices attached to the domain.
	devices := &libvirtxml.DomainDeviceList{
		Controllers: []libvirtxml.DomainController{
			{
				Type:  "pci",
				Model: "pcie-root",
			},
		},
		Disks:      disks,
		Interfaces: interfaces,
		Consoles:   []libvirtxml.DomainConsole{console},
	}

	if spec.WithTPM {
		tpmModel := "tpm-tis"
		if detectLibvirtArch() == "aarch64" {
			tpmModel = "tpm-tis-device"
		}
		// Note that the 'swtpm' TPM Emulator must be installed on the host.
		devices.TPMs = append(devices.TPMs, libvirtxml.DomainTPM{
			Model: tpmModel,
			Backend: &libvirtxml.DomainTPMBackend{
				Emulator: &libvirtxml.DomainTPMBackendEmulator{
					Version: "2.0",
					Debug:   5,
					ActivePCRBanks: &libvirtxml.DomainTPMBackendPCRBanks{
						SHA256: &libvirtxml.DomainTPMBackendPCRBank{},
					},
					Profile: &libvirtxml.DomainTPMBackendProfile{
						Source:         "local:restricted",
						RemoveDisabled: "check",
						Name:           "custom:restricted",
					},
				},
			},
		})
	}

	// Set speed=1000 and duplex=full on all virtio-net NICs so the guest
	// MII/bonding subsystem can determine link status. libvirt's XML does not
	// expose these properties natively for virtio-net; qemu:override would work
	// but requires libvirt >= 8.6. Using -global covers all virtio-net-pci
	// instances regardless of libvirt version.
	qemuCmdline := &libvirtxml.DomainQEMUCommandline{
		Args: []libvirtxml.DomainQEMUCommandlineArg{
			{Value: "-global"},
			{Value: "virtio-net-pci.speed=1000"},
			{Value: "-global"},
			{Value: "virtio-net-pci.duplex=full"},
		},
	}

	// Now construct the domain, inserting the previously built disks & domainOS.
	domain := libvirtxml.Domain{
		Type:    "kvm",
		Name:    prefixedName(name),
		OS:      domainOS,
		SysInfo: sysInfos,
		Memory: &libvirtxml.DomainMemory{
			Value: memKiB,
			Unit:  "KiB",
		},
		VCPU: &libvirtxml.DomainVCPU{
			Value: spec.CPUs,
		},
		CPU: &libvirtxml.DomainCPU{
			Mode: "host-passthrough", // expose host CPU features
			Topology: &libvirtxml.DomainCPUTopology{
				Sockets: 1,
				Cores:   int(spec.CPUs),
				Threads: 1,
			},
		},
		Features:        features,
		Devices:         devices,
		QEMUCommandline: qemuCmdline,
	}

	xmlStr, err := domain.Marshal()
	if err != nil {
		err = fmt.Errorf("failed to marshal domain %q XML: %w", name, err)
		log.Error(err)
		return err
	}
	log.Debugf("Device %q XML definition:\n%s", name, xmlStr)

	dom, err := p.conn.DomainDefineXML(xmlStr)
	if err != nil {
		err = fmt.Errorf("failed to define domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	log.Infof("Device %q defined in powered-off state", name)
	return nil
}

// TeardownDevice stops the device (if running) and removes it completely,
// including all associated resources (disks, network interfaces, NVRAM, etc.).
func (p *LibvirtProvider) TeardownDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)

	// Lookup the domain by name
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	// Destroy the domain if it is running
	state, _, err := dom.GetState()
	if err == nil && state == libvirt.DOMAIN_RUNNING {
		if err := dom.Destroy(); err != nil {
			log.Warnf("Failed to destroy running domain %q: %v", name, err)
		} else {
			log.Infof("Destroyed running domain %q", name)
		}
	}

	// Determine if domain has NVRAM
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		log.Warnf("Failed to get XML description for domain %q: %v", name, err)
	}

	hasNvram := strings.Contains(xmlDesc, "<nvram>")
	log.Debugf("Domain %q has NVRAM: %t", name, hasNvram)

	// Undefine domain, including NVRAM if present
	var undefineFlags libvirt.DomainUndefineFlagsValues
	if hasNvram {
		undefineFlags = libvirt.DOMAIN_UNDEFINE_NVRAM
	}
	if err := dom.UndefineFlags(undefineFlags); err != nil {
		err = fmt.Errorf("failed to undefine domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	log.Infof("Domain %q was undefined", name)

	// Garbage-collect unused networks
	p.teardownUnusedNetworks(log)

	return nil
}

// PowerOnDevice starts a previously defined domain.
func (p *LibvirtProvider) PowerOnDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	if err := dom.Create(); err != nil {
		err = fmt.Errorf("failed to power ON domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	log.Infof("Device %q was powered ON", name)

	// Enable LACP forwarding on xconnect bridges.
	// This must run after domain start because libvirt creates and attaches
	// tap devices to the bridge at that point.
	if err := enableLACPForwardingOnXConnectBridges(); err != nil {
		log.Warnf("Failed to enable LACP forwarding: %v", err)
	}
	return nil
}

// PowerOffDevice hard-power-offs (destroy) the domain.
func (p *LibvirtProvider) PowerOffDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	if err := dom.Destroy(); err != nil {
		err = fmt.Errorf("failed to power OFF domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	log.Infof("Device %q was powered OFF", name)
	return nil
}

// ShutdownDevice gracefully shuts the guest (ACPI).
func (p *LibvirtProvider) ShutdownDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	if err := dom.Shutdown(); err != nil {
		err = fmt.Errorf("failed to shutdown domain %q: %w", name, err)
		log.Error(err)
		return err
	}

	// Optionally wait for it to stop (respecting ctx)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			log.Error(err)
			return err
		case <-ticker.C:
			state, _, err := dom.GetState()
			if err != nil {
				err = fmt.Errorf("failed to get domain %q state: %w", name, err)
				log.Error(err)
				return err
			}
			if state == libvirt.DOMAIN_SHUTOFF {
				log.Infof("Device %q was shutdown", name)
				return nil
			}
		}
	}
}

// RebootDevice performs a hard reboot.
func (p *LibvirtProvider) RebootDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	defer dom.Free()

	if err := dom.Reboot(0); err != nil {
		err = fmt.Errorf("failed to reboot domain %q: %w", name, err)
		log.Error(err)
		return err
	}
	return nil
}

// GetDeviceConsoleOutput retrieves the console output (serial console) of the device.
// Returns the console output as a string, or an error if unavailable.
func (p *LibvirtProvider) GetDeviceConsoleOutput(
	ctx context.Context, name string) (string, error) {
	log := logger.FromContext(ctx)
	// Get path to console logfile (per device)
	logfile := p.getDeviceConsoleLogFile(name)
	if logfile == "" {
		err := fmt.Errorf("console log file not configured for device %q", name)
		log.Error(err)
		return "", err
	}
	data, err := os.ReadFile(logfile)
	if err != nil {
		err = fmt.Errorf("failed to read console log %q: %w", logfile, err)
		log.Error(err)
		return "", err
	}
	return string(data), nil
}

// AttachToDeviceConsole returns stream attached to the device's serial console.
func (p *LibvirtProvider) AttachToDeviceConsole(ctx context.Context,
	name string) (stream io.ReadWriteCloser, echoed, telnet bool, err error) {
	log := logger.FromContext(ctx)
	// libvirt's TCP serial echoes back the user input.
	echoed = true
	// Telnet protocol is enabled.
	telnet = true
	// Get TCP port for the device console
	port, err := p.getDeviceConsolePort(name)
	if err != nil {
		err = fmt.Errorf("failed to get console TCP port for device %q: %w",
			name, err)
		log.Error(err)
		return nil, echoed, telnet, err
	}
	hostIP, err := p.getLibvirtHostIP()
	if err != nil {
		log.Error(err)
		return nil, echoed, telnet, err
	}
	consoleAddr := net.JoinHostPort(hostIP.String(), strconv.Itoa(port))
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", consoleAddr)
	if err != nil {
		err = fmt.Errorf("failed to connect to device %q console on port %d: %w",
			name, port, err)
		log.Error(err)
		return nil, echoed, telnet, err
	}
	return conn, echoed, telnet, nil
}

// GetDeviceStatus returns current device status.
func (p *LibvirtProvider) GetDeviceStatus(
	ctx context.Context, name string) (DeviceStatus, error) {
	log := logger.FromContext(ctx)
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		err = fmt.Errorf("failed to lookup domain %q: %w", name, err)
		log.Error(err)
		return DeviceStatusUnknown, err
	}
	defer dom.Free()

	state, _, err := dom.GetState()
	if err != nil {
		err = fmt.Errorf("failed to get domain %q state: %w", name, err)
		log.Error(err)
		return DeviceStatusUnknown, err
	}
	return deviceStatusFromLibvirtState(state), nil
}

// GetDeviceUplinkIPs returns all IP addresses assigned to the uplink interfaces.
func (p *LibvirtProvider) GetDeviceUplinkIPs(
	ctx context.Context, devName string) (ips []net.IP, err error) {
	log := logger.FromContext(ctx)
	prefixedDevName := prefixedName(devName)

	// Lookup the domain
	dom, err := p.conn.LookupDomainByName(prefixedDevName)
	if err != nil {
		var lverr libvirt.Error
		if errors.As(err, &lverr) && lverr.Code == libvirt.ERR_NO_DOMAIN {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer dom.Free()

	// Get domain XML
	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		err = fmt.Errorf("failed to get XML for domain %q: %w", devName, err)
		log.Error(err)
		return nil, err
	}

	var domain libvirtxml.Domain
	if err := domain.Unmarshal(xmlDesc); err != nil {
		err = fmt.Errorf("failed to parse XML for domain %q: %w", devName, err)
		log.Error(err)
		return nil, err
	}

	for _, iface := range domain.Devices.Interfaces {
		if iface.Source == nil || iface.Source.Network == nil {
			continue
		}
		if iface.Source.Network.Network != uplinkNetwork {
			continue
		}
		if iface.MAC == nil || iface.MAC.Address == "" {
			continue
		}

		// Lookup network
		netObj, err := p.conn.LookupNetworkByName(iface.Source.Network.Network)
		if err != nil {
			log.Warnf("failed to lookup network %q: %v", uplinkNetwork, err)
			continue
		}

		leases, err := netObj.GetDHCPLeases()
		netObj.Free()
		if err != nil {
			log.Warnf("failed to get DHCP leases for network %q: %v", uplinkNetwork, err)
			continue
		}

		for _, lease := range leases {
			if lease.Mac == iface.MAC.Address {
				if ip := net.ParseIP(lease.IPaddr); ip != nil {
					ips = append(ips, ip)
				}
			}
		}
	}
	return ips, nil
}

// WatchDeviceStatus returns a channel that receives status updates for a device.
// The first value sent is always the current status.
func (p *LibvirtProvider) WatchDeviceStatus(
	ctx context.Context, name string) <-chan DeviceStatus {
	ch := make(chan DeviceStatus, 10)

	// Add this channel to the list of watchers
	p.mutex.Lock()
	p.watchers[name] = append(p.watchers[name], ch)
	p.mutex.Unlock()

	go func() {
		defer func() {
			// Remove watcher from the list when context is canceled or goroutine exits.
			p.mutex.Lock()
			defer p.mutex.Unlock()
			wlist := p.watchers[name]
			for i, c := range wlist {
				if c == ch {
					p.watchers[name] = append(wlist[:i], wlist[i+1:]...)
					break
				}
			}
			close(ch)
		}()

		// Send initial status
		st, err := p.GetDeviceStatus(ctx, name)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				ch <- DeviceStatusUnknown
			}
			return
		}
		ch <- st

		// Wait until context cancellation
		<-ctx.Done()
	}()

	return ch
}

// ListDevices returns the names of all devices created by this provider.
func (p *LibvirtProvider) ListDevices(ctx context.Context) ([]string, error) {
	log := logger.FromContext(ctx)
	doms, err := p.conn.ListAllDomains(0)
	if err != nil {
		err = fmt.Errorf("failed to list domains: %w", err)
		log.Error(err)
		return nil, err
	}
	defer func() {
		for _, d := range doms {
			d.Free()
		}
	}()

	var devices []string
	for _, d := range doms {
		name, err := d.GetName()
		if err != nil {
			continue
		}
		if original := unprefixedName(name); original != "" {
			devices = append(devices, original)
		}
	}
	return devices, nil
}

// TeardownAll removes all domains and networks created by this Provider.
func (p *LibvirtProvider) TeardownAll(ctx context.Context) error {
	log := logger.FromContext(ctx)

	// Teardown domains first
	doms, err := p.conn.ListAllDomains(0)
	if err != nil {
		err = fmt.Errorf("failed to list domains: %w", err)
		log.Error(err)
		return err
	}
	for _, d := range doms {
		name, _ := d.GetName()
		if strings.HasPrefix(name, namePrefix) {
			origName := unprefixedName(name)
			if err := p.TeardownDevice(ctx, origName); err != nil {
				log.Warnf("failed to teardown device %q: %v", origName, err)
			}
			// Remove console log file
			consoleLogFile := p.getDeviceConsoleLogFile(origName)
			if err := os.Remove(consoleLogFile); err != nil && !os.IsNotExist(err) {
				log.Warnf("failed to remove console log file %q: %v",
					consoleLogFile, err)
			}
			// Optionally clean up empty parent dir
			_ = os.Remove(filepath.Dir(consoleLogFile))
		}
		d.Free()
	}

	// Then remove any zombie networks
	nets, err := p.conn.ListAllNetworks(0)
	if err != nil {
		return fmt.Errorf("list networks: %w", err)
	}
	for _, n := range nets {
		name, _ := n.GetName()
		if strings.HasPrefix(name, networkPrefix) {
			if err = p.removeNetwork(log, name); err != nil {
				log.Warnf("failed to remove network %q: %v", name, err)
			}
		}
		n.Free()
	}

	return nil
}

// --------- helpers ---------

// detectLibvirtArch returns the host's CPU architecture in the format suitable
// for libvirt/QEMU.
func detectLibvirtArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH // fallback
	}
}

func (p *LibvirtProvider) getLibvirtHostIP() (net.IP, error) {
	if utils.RunningInContainer() && !utils.ContainerUsingHostNetwork() {
		// If running inside a container and NOT using the host network,
		// the libvirt host IP is the container's default gateway IP.
		gwIP, _, err := utils.GetDefaultGateway(netlink.FAMILY_V4)
		if err != nil {
			err = fmt.Errorf("failed to determine libvirt host IP: %v", err)
			return nil, err
		}
		return gwIP, nil
	}
	// Running in the same network namespace as libvirt
	return ipv4Loopback, nil
}

// lookupDomainByName retrieves a libvirt Domain object by its logical name.
func (p *LibvirtProvider) lookupDomainByName(name string) (*libvirt.Domain, error) {
	dom, err := p.conn.LookupDomainByName(prefixedName(name))
	if err != nil {
		var lverr libvirt.Error
		if errors.As(err, &lverr) {
			if lverr.Code == libvirt.ERR_NO_DOMAIN {
				return nil, ErrNotFound
			}
		}
		return nil, err
	}
	return dom, nil
}

// ReconfigureDeviceDisks updates the disk list of a stopped domain by
// undefining and redefining it with a new disk set. The domain UUID is
// preserved so libvirt's swtpm state (keyed by UUID) survives the operation.
// UEFI NVRAM is preserved by undefining without the NVRAM flag.
// The domain must be in the stopped (shut-off) state before calling this.
func (p *LibvirtProvider) ReconfigureDeviceDisks(
	ctx context.Context, name string, newDisks []DiskImage) error {
	log := logger.FromContext(ctx)

	dom, err := p.lookupDomainByName(name)
	if err != nil {
		return fmt.Errorf("failed to lookup domain %q: %w", name, err)
	}
	defer dom.Free()

	state, _, err := dom.GetState()
	if err != nil {
		return fmt.Errorf("failed to get state of domain %q: %w", name, err)
	}
	if state != libvirt.DOMAIN_SHUTOFF {
		err = fmt.Errorf(
			"domain %q must be stopped before reconfiguring disks (state: %v)",
			name, state)
		return err
	}

	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return fmt.Errorf("failed to get XML description for domain %q: %w", name, err)
	}
	var domain libvirtxml.Domain
	if err := domain.Unmarshal(xmlDesc); err != nil {
		return fmt.Errorf("failed to unmarshal domain XML for %q: %w", name, err)
	}

	// Rebuild virtio data disks; leave any non-virtio entries (e.g. CDROMs) in place.
	var keep []libvirtxml.DomainDisk
	for _, d := range domain.Devices.Disks {
		if d.Target == nil || d.Target.Bus != "virtio" {
			keep = append(keep, d)
		}
	}
	for i, disk := range newDisks {
		diskType := "qcow2"
		if disk.Format == DiskImageFormatRaw {
			diskType = "raw"
		}
		absPath, err := utils.ResolveFile(disk.Path)
		if err != nil {
			return fmt.Errorf("failed to resolve disk path %q: %w", disk.Path, err)
		}
		keep = append(keep, libvirtxml.DomainDisk{
			Device: "disk",
			Driver: &libvirtxml.DomainDiskDriver{
				Name: "qemu",
				Type: diskType,
			},
			Source: &libvirtxml.DomainDiskSource{
				File: &libvirtxml.DomainDiskSourceFile{
					File: absPath,
				},
			},
			Target: &libvirtxml.DomainDiskTarget{
				Dev: fmt.Sprintf("vd%c", rune('a'+i)),
				Bus: "virtio",
			},
		})
	}
	domain.Devices.Disks = keep

	updatedXML, err := domain.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal updated domain XML for %q: %w", name, err)
	}

	// Keep NVRAM so OVMF_VARS.fd survives the undefine/redefine cycle.
	if err := dom.UndefineFlags(libvirt.DOMAIN_UNDEFINE_KEEP_NVRAM); err != nil {
		return fmt.Errorf("failed to undefine domain %q: %w", name, err)
	}

	if _, err := p.conn.DomainDefineXML(updatedXML); err != nil {
		// Best-effort rollback: restore the original definition so teardown can proceed.
		_, _ = p.conn.DomainDefineXML(xmlDesc)
		return fmt.Errorf("failed to redefine domain %q after disk reconfiguration: %w",
			name, err)
	}
	log.Infof("Reconfigured disk list for domain %q (%d disk(s))", name, len(newDisks))
	return nil
}

// getDeviceConsoleLogFile returns the filesystem path for storing the console log
// for a given device name.
func (p *LibvirtProvider) getDeviceConsoleLogFile(name string) string {
	return filepath.Join(os.TempDir(),
		"evetest-libvirt-consoles",
		fmt.Sprintf("%s.log", name))
}

// getDeviceConsolePort returns the TCP port number used by the serial console
// of the specified device.
func (p *LibvirtProvider) getDeviceConsolePort(name string) (int, error) {
	dom, err := p.lookupDomainByName(name)
	if err != nil {
		return 0, err
	}
	defer dom.Free()

	xmlDesc, err := dom.GetXMLDesc(0)
	if err != nil {
		return 0, err
	}
	var domain libvirtxml.Domain
	if err := domain.Unmarshal(xmlDesc); err != nil {
		return 0, err
	}

	for _, serial := range domain.Devices.Serials {
		if serial.Source != nil && serial.Source.TCP != nil {
			port, _ := strconv.Atoi(serial.Source.TCP.Service)
			return port, nil
		}
	}
	return 0, ErrNotFound
}

// ensureUplinkNetwork creates or ensures a NAT network used for uplink connectivity
// exists.
func (p *LibvirtProvider) ensureUplinkNetwork(log *logrus.Entry) error {
	netName := uplinkNetwork
	network, err := p.conn.LookupNetworkByName(netName)
	if err == nil {
		defer network.Free()
		return nil // already exists
	}

	// Build network XML
	networkXML := &libvirtxml.Network{
		Name: netName,
		Forward: &libvirtxml.NetworkForward{
			Mode: "nat",
		},
		Bridge: &libvirtxml.NetworkBridge{
			Name: netName,
		},
	}

	bridgeIP := utils.GetFirstHostIP(p.conf.SDNUplinkIPv4Subnet)
	dhcpStart := utils.GetNextIP(bridgeIP)
	dhcpEnd := utils.GetLastHostIP(p.conf.SDNUplinkIPv4Subnet)
	networkXML.IPs = append(networkXML.IPs,
		libvirtxml.NetworkIP{
			Family:  "ipv4",
			Address: bridgeIP.String(),
			Netmask: net.IP(p.conf.SDNUplinkIPv4Subnet.Mask).String(),
			DHCP: &libvirtxml.NetworkDHCP{
				Ranges: []libvirtxml.NetworkDHCPRange{
					{
						Start: dhcpStart.String(),
						End:   dhcpEnd.String(),
					},
				},
			},
		},
	)

	if p.conf.SDNUplinkIPv6Subnet != nil {
		bridgeIPv6 := utils.GetFirstHostIP(p.conf.SDNUplinkIPv6Subnet)
		networkXML.IPs = append(networkXML.IPs,
			libvirtxml.NetworkIP{
				Family:  "ipv6",
				Address: bridgeIPv6.String(),
				Prefix:  utils.GetSubnetPrefixLen(p.conf.SDNUplinkIPv6Subnet),
			},
		)
	}

	// Define and start network
	netDef, err := networkXML.Marshal()
	if err != nil {
		err = fmt.Errorf("failed to marshal network %q XML: %w", netName, err)
		log.Error(err)
		return err
	}
	log.Debugf("Network %q XML definition:\n%s", netName, netDef)
	network, err = p.conn.NetworkDefineXML(netDef)
	if err != nil {
		err = fmt.Errorf("failed to define network %q: %w", netName, err)
		log.Error(err)
		return err
	}
	defer network.Free()

	if err := network.SetAutostart(true); err != nil {
		log.Warnf("failed to enable autostart for network %q: %v", netName, err)
	}
	if err := network.Create(); err != nil {
		err = fmt.Errorf("failed to start network %q: %w", netName, err)
		log.Error(err)
		return err
	}

	log.Infof("Created network %q", netName)
	return nil
}

// ensureXConnectNetwork creates or ensures a bridge network exists for
// a point-to-point link.
func (p *LibvirtProvider) ensureXConnectNetwork(log *logrus.Entry,
	netName string) error {
	net, err := p.conn.LookupNetworkByName(netName)
	if err == nil {
		defer net.Free()
		return nil // already exists
	}

	// bridge network XML
	netXML := libvirtxml.Network{
		Name: netName,
		Bridge: &libvirtxml.NetworkBridge{
			Name: netName,
			STP:  "off",
		},
	}

	xmlStr, err := netXML.Marshal()
	if err != nil {
		err = fmt.Errorf("failed to marshal network %q XML: %w", netName, err)
		log.Error(err)
		return err
	}
	log.Debugf("Network %q XML definition:\n%s", netName, xmlStr)
	net, err = p.conn.NetworkDefineXML(xmlStr)
	if err != nil {
		err = fmt.Errorf("failed to define network %q XML: %w", netName, err)
		log.Error(err)
		return err
	}
	defer net.Free()

	if err = net.Create(); err != nil {
		err = fmt.Errorf("failed to create network %q: %w", netName, err)
		log.Error(err)
		return err
	}
	if err = net.SetAutostart(true); err != nil {
		err = fmt.Errorf("failed to autostart network %q: %w", netName, err)
		log.Error(err)
		return err
	}

	// Enable forwarding of link-local protocols so the xconnect bridge behaves
	// like a transparent cable.
	// Note: LACP (bit 2) cannot be set in the bridge-level group_fwd_mask
	// (kernel rejects BR_GROUPFWD_RESTRICTED). It is enabled separately via
	// the per-port IFLA_BRPORT_GROUP_FWD_MASK in enableLACPForwardingOnXConnectBridges.
	groupFwdMask := "0x4008" // EAPOL + LLDP
	path := fmt.Sprintf("/sys/class/net/%s/bridge/group_fwd_mask", netName)
	if err := os.WriteFile(path, []byte(groupFwdMask), 0o644); err != nil {
		err = fmt.Errorf("failed to set group_fwd_mask (%s) on bridge %q: %w",
			groupFwdMask, netName, err)
		log.Error(err)
		return err
	}

	// Prevent the host from answering ARP for its own IPs on this bridge.
	// Without this, VMs resolve the host's management IP to the bridge MAC and
	// send traffic directly to the host instead of through the SDN VM.
	arpIgnorePath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/arp_ignore", netName)
	if err := os.WriteFile(arpIgnorePath, []byte("1"), 0o644); err != nil {
		err = fmt.Errorf("failed to set arp_ignore on bridge %q: %w", netName, err)
		log.Error(err)
		return err
	}

	// Docker sets bridge-nf-call-iptables=1 (and ip6tables equivalent) globally,
	// which overrides the per-bridge nf_call_iptables=0 set by libvirt. As a
	// result, Docker's DNAT rules in nat PREROUTING intercept bridged packets
	// before they reach the SDN VM. Insert a RETURN rule ahead of Docker's rules
	// in both iptables and ip6tables to skip DNAT for all traffic on this bridge.
	if err := ensureXConnectNATReturn(netName); err != nil {
		err = fmt.Errorf("failed to add iptables RETURN rule for bridge %q: %w",
			netName, err)
		log.Error(err)
		return err
	}

	log.Infof("Created network %q", netName)
	return nil
}

// domainLifecycleCallback is called by libvirt for all domain lifecycle events.
func (p *LibvirtProvider) domainLifecycleCallback(
	c *libvirt.Connect, d *libvirt.Domain, event *libvirt.DomainEventLifecycle) {
	if event == nil {
		return
	}
	domName, err := d.GetName()
	if err != nil {
		// ignore domains we can't identify
		return
	}
	// libvirt returns the full prefixed name; watchers are keyed by unprefixed name.
	name := unprefixedName(domName)
	status := deviceStatusFromLibvirtEvent(*event)

	// Send the status update to all registered watchers for this domain
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, ch := range p.watchers[name] {
		select {
		case ch <- status:
		default:
			// drop if the channel is full
		}
	}
}

// deviceStatusFromLibvirtState converts a libvirt DomainState into the provider's
// DeviceStatus. Maps known libvirt states (running, shutoff, paused, etc.)
// to the corresponding DeviceStatus enum.
func deviceStatusFromLibvirtState(state libvirt.DomainState) DeviceStatus {
	switch state {
	case libvirt.DOMAIN_RUNNING:
		return DeviceStatusRunning
	case libvirt.DOMAIN_SHUTOFF:
		return DeviceStatusStopped
	case libvirt.DOMAIN_BLOCKED, libvirt.DOMAIN_PAUSED:
		return DeviceStatusSuspended
	case libvirt.DOMAIN_CRASHED:
		return DeviceStatusCrashed
	default:
		return DeviceStatusUnknown
	}
}

// deviceStatusFromLibvirtEvent converts a libvirt DomainEventLifecycle into
// the provider's DeviceStatus. Interprets lifecycle events such as started, stopped,
// crashed, or suspended into the corresponding DeviceStatus.
func deviceStatusFromLibvirtEvent(event libvirt.DomainEventLifecycle) DeviceStatus {
	switch event.Event {
	case libvirt.DOMAIN_EVENT_STARTED:
		return DeviceStatusRunning
	case libvirt.DOMAIN_EVENT_STOPPED:
		return DeviceStatusStopped
	case libvirt.DOMAIN_EVENT_CRASHED:
		return DeviceStatusCrashed
	case libvirt.DOMAIN_EVENT_SUSPENDED,
		libvirt.DOMAIN_EVENT_PMSUSPENDED:
		return DeviceStatusSuspended
	default:
		return DeviceStatusUnknown
	}
}

// isNetworkInUse checks if any domain still uses the given network.
func (p *LibvirtProvider) isNetworkInUse(log *logrus.Entry,
	netName string) (bool, error) {
	doms, err := p.conn.ListAllDomains(0)
	if err != nil {
		err = fmt.Errorf("failed to list domains: %w", err)
		log.Error(err)
		return false, err
	}
	defer func() {
		for _, d := range doms {
			d.Free()
		}
	}()

	for _, d := range doms {
		xmlDesc, err := d.GetXMLDesc(0)
		if err != nil {
			continue
		}
		var domCfg libvirtxml.Domain
		if err := domCfg.Unmarshal(xmlDesc); err != nil {
			continue
		}
		for _, iface := range domCfg.Devices.Interfaces {
			if iface.Source != nil && iface.Source.Network != nil &&
				iface.Source.Network.Network == netName {
				return true, nil
			}
		}
	}
	return false, nil
}

// removeNetwork destroys and undefines a libvirt network with the given prefixed name.
// If the network does not exist, it silently returns without error.
// Logs success or any errors encountered during destruction or undefinition.
func (p *LibvirtProvider) removeNetwork(log *logrus.Entry, netName string) error {
	net, err := p.conn.LookupNetworkByName(netName)
	if err != nil {
		var lverr libvirt.Error
		if errors.As(err, &lverr) {
			if lverr.Code == libvirt.ERR_NO_NETWORK {
				return nil
			}
		}
		err = fmt.Errorf("failed to lookup network %q: %w", netName, err)
		log.Error(err)
		return err
	}
	defer net.Free()
	_ = net.Destroy()
	if err = net.Undefine(); err != nil {
		err = fmt.Errorf("failed to undefine network %q: %w", netName, err)
		log.Error(err)
		return err
	}
	if strings.HasPrefix(netName, xconnectBridgePrefix) {
		if err := deleteXConnectNATReturn(netName); err != nil {
			log.Warnf("Failed to remove iptables RETURN rule for bridge %q: %v",
				netName, err)
		}
	}
	log.Infof("Removed network %q", netName)
	return err
}

// ensureXConnectNATReturn inserts nat PREROUTING and POSTROUTING RETURN rules
// for the bridge in both iptables and ip6tables if they do not already exist.
// PREROUTING: prevents host DNAT rules from intercepting bridged traffic before
// it reaches the SDN VM. POSTROUTING: prevents host SNAT/MASQUERADE rules (e.g.
// Docker's) from rewriting source IPs of traffic forwarded through the bridge,
// keeping inter-VM traffic isolated from the host NAT configuration.
func ensureXConnectNATReturn(brName string) error {
	// PREROUTING uses -i (input); POSTROUTING uses -o (output) — iptables
	// does not allow --in-interface in POSTROUTING.
	chainFlag := map[string]string{
		"PREROUTING":  "-i",
		"POSTROUTING": "-o",
	}
	for _, cmd := range []string{"iptables", "ip6tables"} {
		for chain, flag := range chainFlag {
			check := exec.Command(cmd, "-t", "nat", "-C", chain,
				flag, brName, "-j", "RETURN")
			if check.Run() == nil {
				continue // rule already present
			}
			out, err := exec.Command(cmd, "-t", "nat", "-I", chain, "1",
				flag, brName, "-j", "RETURN").CombinedOutput()
			if err != nil {
				return fmt.Errorf("%s insert %s: %w: %s", cmd, chain, err,
					strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// deleteXConnectNATReturn removes the nat PREROUTING and POSTROUTING RETURN
// rules for the bridge from both iptables and ip6tables.
func deleteXConnectNATReturn(brName string) error {
	chainFlag := map[string]string{
		"PREROUTING":  "-i",
		"POSTROUTING": "-o",
	}
	for _, cmd := range []string{"iptables", "ip6tables"} {
		for chain, flag := range chainFlag {
			out, err := exec.Command(cmd, "-t", "nat", "-D", chain,
				flag, brName, "-j", "RETURN").CombinedOutput()
			if err != nil {
				s := strings.TrimSpace(string(out))
				if strings.Contains(s, "No chain/target/match") ||
					strings.Contains(s, "Bad rule") {
					continue // rule was not present, nothing to do
				}
				return fmt.Errorf("%s delete %s: %w: %s", cmd, chain, err, s)
			}
		}
	}
	return nil
}

// teardownUnusedNetworks removes all evetest-* networks that are not used by any domain.
func (p *LibvirtProvider) teardownUnusedNetworks(log *logrus.Entry) {
	nets, err := p.conn.ListAllNetworks(0)
	if err != nil {
		log.Printf("warn: failed to list networks: %v", err)
		return
	}
	defer func() {
		for _, n := range nets {
			n.Free()
		}
	}()

	for _, n := range nets {
		name, err := n.GetName()
		if err != nil {
			continue
		}
		if !strings.HasPrefix(name, networkPrefix) {
			continue
		}
		inUse, err := p.isNetworkInUse(log, name)
		if err != nil {
			// Error is logged by isNetworkInUse
			continue
		}
		if !inUse {
			err = p.removeNetwork(log, name)
			if err != nil {
				// Error is logged by removeNetwork
				continue
			}
		}
	}

	cleanupOrphanedXConnectNATRules(log)
}

// cleanupOrphanedXConnectNATRules removes nat PREROUTING/POSTROUTING RETURN rules
// for evetest-x-* bridges that no longer exist as network interfaces.
func cleanupOrphanedXConnectNATRules(log *logrus.Entry) {
	// Scan iptables (IPv4) save output — bridge names are the same in ip6tables.
	brNames := make(map[string]struct{})
	for _, chain := range []string{"PREROUTING", "POSTROUTING"} {
		out, err := exec.Command("iptables", "-t", "nat", "-S", chain).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, xconnectBridgePrefix) {
				continue
			}
			fields := strings.Fields(line)
			for i, f := range fields {
				if (f == "-i" || f == "-o") && i+1 < len(fields) &&
					strings.HasPrefix(fields[i+1], xconnectBridgePrefix) {
					brNames[fields[i+1]] = struct{}{}
				}
			}
		}
	}
	for brName := range brNames {
		if _, err := netlink.LinkByName(brName); err == nil {
			continue // bridge still exists
		}
		if err := deleteXConnectNATReturn(brName); err != nil {
			log.Warnf("Failed to remove orphaned iptables rules for bridge %q: %v",
				brName, err)
		}
	}
}
