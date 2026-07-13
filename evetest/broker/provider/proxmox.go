// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lf-edge/eve/evetest/constants"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	"github.com/lf-edge/eve/evetest/logger"
	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/luthermonson/go-proxmox"
	"github.com/sirupsen/logrus"
)

// ProxmoxProvider manages the lifecycle of VMs on a Proxmox VE host purely
// through the Proxmox REST API (using github.com/luthermonson/go-proxmox).
type ProxmoxProvider struct {
	conf  ProxmoxProviderConf
	mutex sync.Mutex

	client *proxmox.Client

	// supportedArchs is the node architecture, learned at construction time.
	supportedArchs []api.ArchType

	// watchers holds all registered watchers for device lifecycle events.
	// The key is device name (without prefix).
	watchers map[string][]chan DeviceStatus

	// devices created by SetupDevice (and not yet removed by TeardownDevice).
	// The key is device name (without prefix).
	devices map[string]*proxmoxDevice

	// networks (SDN VNets) created by SetupDevice and used by at least one
	// device. The key is the unprefixed evetest network name.
	networks map[string]*proxmoxNetwork
}

// ProxmoxProviderConf : configuration for the Proxmox provider.
type ProxmoxProviderConf struct {
	CommonProviderConf

	// APIURL is the Proxmox VE REST API base URL,
	// e.g. "https://192.168.1.50:8006/api2/json".
	APIURL string
	// Password is the password for the "root@pam" Proxmox user. An API token
	// cannot be used here: Proxmox hardcodes several VM config options (e.g.
	// "hookscript", "args") as settable only by a real "root@pam" session,
	// regardless of a token's assigned privileges/ACLs.
	Password string
	// Node is the Proxmox node name on which to create VMs (e.g. "pve"). If
	// empty, it is auto-detected on single-node installations (required only for
	// multi-node clusters).
	Node string
	// Storage is the storage ID used for VM disks (e.g. "local-lvm").
	Storage string
	// ImportStorage is the storage ID (with the "import" content type enabled,
	// e.g. "local") that disk images are uploaded to before being imported into
	// Storage. Defaults to "local".
	ImportStorage string
	// TLSSkipVerify disables TLS certificate verification (self-signed PVE cert).
	TLSSkipVerify bool
}

type proxmoxDevice struct {
	name string
	spec DeviceSpec
	vmID int

	ifaces []proxmoxIface
	status DeviceStatus

	// firmwareVolIDs holds the import-storage volume IDs of the uploaded custom
	// OVMF CODE/VARS files (empty unless custom UEFI firmware is used). Unlike
	// disk import sources, these are read live by QEMU for the VM's lifetime and
	// are removed only on teardown.
	firmwareVolIDs []string

	consoleLog    string
	consoleCancel context.CancelFunc
	consoleDone   chan struct{}
	// consoleMux multiplexes the single underlying console connection the
	// background logger holds open for the device's whole powered-on
	// lifetime (see startConsoleLogger) between that logger and any
	// interactively attached client (AttachToDeviceConsole). PVE's serial0
	// chardev socket does not support multiple simultaneous independent
	// termproxy sessions on the same VM cleanly, so both must share the one
	// connection rather than each opening their own.
	consoleMux *consoleMux
}

type proxmoxIface struct {
	name     string
	mac      net.HardwareAddr
	netName  string // unprefixed evetest network name
	vnet     string // SDN VNet / bridge the interface attaches to
	model    string // PVE config key, e.g. "net0"
	isUplink bool
}

type proxmoxNetwork struct {
	name     string // unprefixed evetest network name
	vnet     string // SDN VNet name (also the Linux bridge VMs attach to)
	isUplink bool
}

// sdnZone is the name of the SDN simple zone used for all evetest networks.
// Proxmox SDN zone names are limited to 8 characters.
const sdnZone = "evetest"

// proxmoxIPAMName is the name of PVE's built-in "pve" IPAM plugin, which is what
// the broker installer configures for the "evetest" zone (see
// deploy/proxmox/installer.sh.tmpl).
const proxmoxIPAMName = "pve"

// proxmoxIPAMEntry mirrors the subset of go-proxmox's IPAM struct GetDeviceUplinkIPs
// actually needs. It's declared locally instead of reusing proxmox.IPAM because that
// type's VMID field is typed string, while PVE's /cluster/sdn/ipams/<name>/status
// endpoint returns vmid as a JSON number for VM-owned entries (and omits it entirely
// for gateway entries), which fails to unmarshal into a string field.
type proxmoxIPAMEntry struct {
	Mac string `json:"mac"`
	IP  string `json:"ip"`
}

// proxmoxHookscriptVolID is the fixed storage volume ID of the host hookscript
// that applies link-local L2 forwarding tweaks (LACP/EAPOL/LLDP/ARP) on the
// xconnect VNet bridges. It is always attached to VMs created by this provider
// and is installed on the Proxmox host by the broker installer (see
// evetest/deploy/proxmox).
const proxmoxHookscriptVolID = "local:snippets/evetest-hook.pl"

// proxmoxTaskPollInterval / proxmoxTaskTimeout bound how long we wait for
// asynchronous Proxmox tasks (VM start/stop, SDN apply, ...) to complete.
const (
	proxmoxTaskPollInterval = 1 * time.Second
	proxmoxTaskTimeout      = 5 * time.Minute
	proxmoxStatusPollPeriod = 2 * time.Second
	proxmoxConnectTimeout   = 30 * time.Second
)

// waitTask waits for task to complete. go-proxmox returns a nil task (with a
// nil error) when PVE completes an operation synchronously without queuing an
// async UPID; treat that as already done instead of calling Wait on it.
func waitTask(ctx context.Context, task *proxmox.Task) error {
	if task == nil {
		return nil
	}
	return task.Wait(ctx, proxmoxTaskPollInterval, proxmoxTaskTimeout)
}

// NewProxmoxProvider creates a new Proxmox provider instance and verifies
// connectivity to the configured Proxmox node.
func NewProxmoxProvider(conf ProxmoxProviderConf) (*ProxmoxProvider, error) {
	if conf.APIURL == "" {
		return nil, fmt.Errorf("proxmox API URL is not configured (%s)",
			constants.EnvPrefix+constants.BrokerProxmoxAPIURLEnv)
	}
	if conf.Password == "" {
		return nil, fmt.Errorf("proxmox root@pam password is not configured (%s)",
			constants.EnvPrefix+constants.BrokerProxmoxPasswordEnv)
	}
	if conf.Storage == "" {
		return nil, fmt.Errorf("proxmox storage is not configured (%s)",
			constants.EnvPrefix+constants.BrokerProxmoxStorageEnv)
	}
	if conf.ImportStorage == "" {
		conf.ImportStorage = "local"
	}

	// Must be the literal root@pam user, not an API token -- see Password's doc
	// comment on ProxmoxProviderConf.
	opts := []proxmox.Option{
		proxmox.WithCredentials(&proxmox.Credentials{
			Username: "root@pam",
			Password: conf.Password,
		}),
	}
	if conf.TLSSkipVerify {
		opts = append(opts, proxmox.WithInsecureSkipVerify())
	}
	client := proxmox.NewClient(conf.APIURL, opts...)

	// Query the node architecture. This also verifies API connectivity and that
	// the configured node exists.
	ctx, cancel := context.WithTimeout(context.Background(), proxmoxConnectTimeout)
	defer cancel()
	archs, err := nodeArchs(ctx, client, conf.Node)
	if err != nil {
		return nil, err
	}

	// Resolve the target node. If none is configured, auto-detect it: a
	// single-node installation has exactly one node, so no configuration is
	// needed; a multi-node cluster requires the node to be specified explicitly.
	if conf.Node == "" {
		ctx, cancel = context.WithTimeout(context.Background(), proxmoxConnectTimeout)
		defer cancel()
		node, err := autoDetectNode(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to Proxmox API at %s: %w",
				conf.APIURL, err)
		}
		conf.Node = node
	}

	return &ProxmoxProvider{
		conf:           conf,
		client:         client,
		supportedArchs: archs,
		watchers:       make(map[string][]chan DeviceStatus),
		devices:        make(map[string]*proxmoxDevice),
		networks:       make(map[string]*proxmoxNetwork),
	}, nil
}

// autoDetectNode returns the single node of a single-node Proxmox installation.
// It errors if there are zero nodes, or more than one (in which case the node
// must be configured explicitly via BROKER_PROXMOX_NODE).
func autoDetectNode(ctx context.Context, client *proxmox.Client) (string, error) {
	nodes, err := client.Nodes(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to list Proxmox nodes: %w", err)
	}
	var names []string
	for _, n := range nodes {
		name := n.Node
		if name == "" {
			name = n.Name
		}
		if name != "" {
			names = append(names, name)
		}
	}
	switch len(names) {
	case 0:
		return "", fmt.Errorf("no Proxmox nodes found")
	case 1:
		return names[0], nil
	default:
		return "", fmt.Errorf("multiple Proxmox nodes found (%s); set %s to choose one",
			strings.Join(names, ", "), constants.BrokerProxmoxNodeEnv)
	}
}

// GetSupportedDeviceArchs returns the node architecture learned at construction
// time. VMs use host-CPU passthrough, so the node architecture is the only one
// supported.
func (p *ProxmoxProvider) GetSupportedDeviceArchs() ([]api.ArchType, error) {
	return p.supportedArchs, nil
}

// nodeArchs reads the architecture of the given Proxmox node from its
// running-kernel machine type (uname -m) in the node status.
// It is also used by the constructor for API connectivity and node-existence check.
//
// The go-proxmox Node struct does not model the "current-kernel" field that
// carries the machine type, so the node status is fetched directly.
func nodeArchs(ctx context.Context, client *proxmox.Client,
	node string) ([]api.ArchType, error) {
	var status struct {
		CurrentKernel struct {
			Machine string `json:"machine"`
		} `json:"current-kernel"`
	}
	if err := client.Get(ctx,
		fmt.Sprintf("/nodes/%s/status", node), &status); err != nil {
		return nil, fmt.Errorf("failed to query status of Proxmox node %q: %w",
			node, err)
	}
	switch status.CurrentKernel.Machine {
	case "x86_64":
		return []api.ArchType{api.ArchType_ARCH_AMD64}, nil
	case "aarch64", "arm64":
		return []api.ArchType{api.ArchType_ARCH_ARM64}, nil
	default:
		return nil, fmt.Errorf(
			"unrecognized architecture %q reported by Proxmox node %q",
			status.CurrentKernel.Machine, node)
	}
}

// Capabilities returns the full capability set (link-local L2 forwarding + TPM),
// same as qemu/libvirt. The host hookscript (proxmoxHookscriptVolID, a deployment
// prerequisite installed by the Proxmox broker installer) applies the link-local
// L2 forwarding tweaks on the xconnect bridges, and TPM is supported via tpmstate0.
func (p *ProxmoxProvider) Capabilities() []api.Capability {
	return fullCapabilitySet()
}

// SetupDevice creates a VM in a powered-off state with the given configuration.
func (p *ProxmoxProvider) SetupDevice(
	ctx context.Context, name string, spec DeviceSpec) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if _, ok := p.devices[name]; ok {
		err := fmt.Errorf("device %q already exists", name)
		log.Error(err)
		return err
	}

	node, err := p.client.Node(ctx, p.conf.Node)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox node %q: %w", p.conf.Node, err)
	}

	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox cluster: %w", err)
	}
	vmID, err := cluster.NextID(ctx)
	if err != nil {
		return fmt.Errorf("failed to allocate VMID for device %q: %w", name, err)
	}

	consoleLog := p.getDeviceConsoleLogFile(name)
	if err := os.MkdirAll(filepath.Dir(consoleLog), 0o755); err != nil {
		return fmt.Errorf("failed to create console log directory for device %q: %w",
			name, err)
	}

	dev := &proxmoxDevice{
		name:       name,
		spec:       spec,
		vmID:       vmID,
		consoleLog: consoleLog,
		consoleMux: newConsoleMux(),
	}

	// Clean up anything already uploaded/created if the function returns before
	// reaching the success path below: otherwise a failure partway through
	// (e.g. firmware upload, VM creation, or its waitTask) leaks multi-GB
	// disk/firmware images on the import storage, and possibly a half-created
	// VM, with no other code path that removes them (dev is only added to
	// p.devices -- and so reachable from destroyDevice -- on success).
	var diskVolIDs []string
	var vmCreated bool
	success := false
	defer func() {
		if success {
			return
		}
		if len(diskVolIDs) > 0 {
			p.deleteImportVolumes(ctx, log, node, diskVolIDs)
		}
		if len(dev.firmwareVolIDs) > 0 {
			p.deleteImportVolumes(ctx, log, node, dev.firmwareVolIDs)
		}
		if vmCreated {
			if vm, vmErr := node.VirtualMachine(ctx, vmID); vmErr != nil {
				log.Warnf("failed to lookup VM %d for cleanup: %v", vmID, vmErr)
			} else if task, delErr := vm.Delete(ctx, &proxmox.VirtualMachineDeleteOptions{
				Purge:                    true,
				DestroyUnreferencedDisks: true,
			}); delErr != nil {
				log.Warnf("failed to delete VM %d during cleanup: %v", vmID, delErr)
			} else if waitErr := waitTask(ctx, task); waitErr != nil {
				log.Warnf("failed waiting for cleanup deletion of VM %d: %v", vmID, waitErr)
			}
		}
	}()

	// Ensure all SDN networks exist and resolve interface -> VNet (bridge).
	sdnChanged := false
	for i, iface := range spec.NetworkInterfaces {
		var network *proxmoxNetwork
		switch {
		case iface.Connection.Uplink != nil:
			network, err = p.ensureUplinkNetwork(ctx)
		case iface.Connection.XConnect != nil:
			xc := iface.Connection.XConnect
			netName := xconnectNetworkName(
				name, iface.Name, xc.PeerDeviceName, xc.PeerInterfaceName)
			network, err = p.ensureXConnectNetwork(ctx, log, netName, &sdnChanged)
		default:
			err = fmt.Errorf("missing ConnectionSpec for interface %q in device %q",
				iface.Name, name)
		}
		if err != nil {
			log.Error(err)
			return err
		}
		mac := iface.MACAddress
		if len(mac) == 0 {
			mac = utils.GenerateMAC(dev.name, iface.Name)
		}
		dev.ifaces = append(dev.ifaces, proxmoxIface{
			name:     iface.Name,
			mac:      mac,
			netName:  network.name,
			vnet:     network.vnet,
			model:    fmt.Sprintf("net%d", i),
			isUplink: network.isUplink,
		})
	}

	// Apply pending SDN changes so the bridges exist before the VM references them.
	if sdnChanged {
		if err := p.applySDN(ctx, log); err != nil {
			return err
		}
	}

	// Upload disk images to the import storage; the returned volume IDs are used
	// both as import-from references and as cleanup targets afterwards.
	diskVolIDs, err = p.uploadDiskImages(ctx, node, dev)
	if err != nil {
		return err
	}

	// Upload custom UEFI firmware (if any) and build the pflash args referencing
	// it. These volumes persist for the VM lifetime (removed on teardown).
	firmwareArgs, err := p.uploadFirmware(ctx, node, dev)
	if err != nil {
		return err
	}

	// Build the VM configuration options and create the VM (stopped).
	options, err := p.buildVMOptions(dev, diskVolIDs, firmwareArgs)
	if err != nil {
		return err
	}
	task, err := node.NewVirtualMachine(ctx, vmID, options...)
	if err != nil {
		return fmt.Errorf("failed to create VM %d for device %q: %w", vmID, name, err)
	}
	// The VM may already exist on the node even if the wait below fails (e.g. PVE
	// queued the task but it times out client-side), so it must be cleaned up too.
	vmCreated = true
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d creation: %w", vmID, err)
	}

	// The import-from sources have been copied into the VM disks during creation;
	// remove the uploaded images to avoid accumulating them on the import storage.
	p.deleteImportVolumes(ctx, log, node, diskVolIDs)
	diskVolIDs = nil

	p.devices[name] = dev
	p.updateDeviceStatus(dev, DeviceStatusStopped)
	success = true
	log.Infof("Device %q prepared as Proxmox VM %d in powered-off state", name, vmID)
	return nil
}

// TeardownDevice stops (if running) and removes the VM, then garbage-collects
// any SDN networks that are no longer in use.
func (p *ProxmoxProvider) TeardownDevice(ctx context.Context, name string) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, ok := p.devices[name]
	if !ok {
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return err
	}
	if err := p.destroyDevice(ctx, log, dev); err != nil {
		return err
	}
	delete(p.devices, name)
	p.teardownUnusedNetworks(ctx, log)
	return nil
}

// PowerOnDevice starts a previously created VM.
func (p *ProxmoxProvider) PowerOnDevice(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, vm, err := p.lookupVM(ctx, name)
	if err != nil {
		return err
	}
	task, err := vm.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start VM %d for device %q: %w", dev.vmID, name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d start: %w", dev.vmID, err)
	}
	p.updateDeviceStatus(dev, DeviceStatusRunning)
	// The VM may have powered itself off from inside the guest (e.g. the EVE
	// installer, after writing the target disk) without going through
	// PowerOffDevice/ShutdownDevice, leaving a stuck logger from the previous
	// boot still "running". Always stop it before starting a fresh one.
	p.stopConsoleLogger(dev)
	p.startConsoleLogger(ctx, dev)
	return nil
}

// PowerOffDevice performs a hard power-off of the VM.
func (p *ProxmoxProvider) PowerOffDevice(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, vm, err := p.lookupVM(ctx, name)
	if err != nil {
		return err
	}
	task, err := vm.Stop(ctx)
	if err != nil {
		return fmt.Errorf("failed to stop VM %d for device %q: %w", dev.vmID, name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d stop: %w", dev.vmID, err)
	}
	p.stopConsoleLogger(dev)
	p.updateDeviceStatus(dev, DeviceStatusStopped)
	return nil
}

// ShutdownDevice performs a graceful (ACPI) shutdown and waits for the guest.
func (p *ProxmoxProvider) ShutdownDevice(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, vm, err := p.lookupVM(ctx, name)
	if err != nil {
		return err
	}
	task, err := vm.Shutdown(ctx)
	if err != nil {
		return fmt.Errorf("failed to shut down VM %d for device %q: %w",
			dev.vmID, name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d shutdown: %w", dev.vmID, err)
	}
	p.stopConsoleLogger(dev)
	p.updateDeviceStatus(dev, DeviceStatusStopped)
	return nil
}

// RebootDevice performs a hard reset of the VM.
func (p *ProxmoxProvider) RebootDevice(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, vm, err := p.lookupVM(ctx, name)
	if err != nil {
		return err
	}
	task, err := vm.Reset(ctx)
	if err != nil {
		return fmt.Errorf("failed to reset VM %d for device %q: %w", dev.vmID, name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d reset: %w", dev.vmID, err)
	}
	return nil
}

// GetDeviceConsoleOutput returns the serial console output captured so far.
func (p *ProxmoxProvider) GetDeviceConsoleOutput(
	ctx context.Context, name string) (string, error) {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	dev, ok := p.devices[name]
	p.mutex.Unlock()
	if !ok {
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return "", err
	}
	data, err := os.ReadFile(dev.consoleLog)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read console log %q: %w", dev.consoleLog, err)
	}
	return string(data), nil
}

// AttachToDeviceConsole returns a stream attached to the VM serial console.
//
// It subscribes to the single console connection the background logger holds
// open for the device's whole powered-on lifetime (see startConsoleLogger)
// rather than opening a second, independent termproxy session: PVE's serial0
// chardev socket does not support multiple simultaneous readers/writers on
// the same VM cleanly, and a competing session starves both of usable data.
func (p *ProxmoxProvider) AttachToDeviceConsole(_ context.Context,
	name string) (stream io.ReadWriteCloser, echoed, telnet bool, err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	dev, ok := p.devices[name]
	if !ok {
		err = fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		return nil, false, false, err
	}
	if dev.consoleCancel == nil {
		err = fmt.Errorf("device %q is not powered on", name)
		return nil, false, false, err
	}
	// The guest serial getty echoes input; termproxy is not the telnet protocol.
	return dev.consoleMux.subscribe(), true, false, nil
}

// GetDeviceStatus returns the current status of the VM.
func (p *ProxmoxProvider) GetDeviceStatus(
	ctx context.Context, name string) (DeviceStatus, error) {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	_, vm, err := p.lookupVM(ctx, name)
	p.mutex.Unlock()
	if err != nil {
		return DeviceStatusUnknown, err
	}
	return mapProxmoxStatus(vm.Status, vm.QMPStatus, log), nil
}

// GetDeviceUplinkIPs returns the IP addresses assigned to the uplink interfaces,
// looked up from the Proxmox SDN IPAM by MAC address.
func (p *ProxmoxProvider) GetDeviceUplinkIPs(
	ctx context.Context, name string) ([]net.IP, error) {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, ok := p.devices[name]
	if !ok {
		err := fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
		log.Error(err)
		return nil, err
	}

	var ipamEntries []proxmoxIPAMEntry
	if err := p.client.Get(ctx,
		fmt.Sprintf("/cluster/sdn/ipams/%s/status", proxmoxIPAMName), &ipamEntries,
	); err != nil {
		return nil, fmt.Errorf("failed to query SDN IPAM: %w", err)
	}

	var ips []net.IP
	for _, iface := range dev.ifaces {
		if !iface.isUplink {
			continue
		}
		ifaceMAC := strings.ToLower(iface.mac.String())
		for _, entry := range ipamEntries {
			if strings.ToLower(entry.Mac) != ifaceMAC {
				continue
			}
			ip := net.ParseIP(entry.IP)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips, nil
}

// WatchDeviceStatus returns a channel that receives status updates for a device.
// The first value sent is always the current status. Proxmox has no per-VM event
// push, so the status is polled.
func (p *ProxmoxProvider) WatchDeviceStatus(
	ctx context.Context, name string) <-chan DeviceStatus {
	ch := make(chan DeviceStatus, 10)

	p.mutex.Lock()
	p.watchers[name] = append(p.watchers[name], ch)
	p.mutex.Unlock()

	go func() {
		defer func() {
			p.mutex.Lock()
			defer p.mutex.Unlock()
			wlist := p.watchers[name]
			for i, c := range wlist {
				if c == ch {
					p.watchers[name] = append(wlist[:i], wlist[i+1:]...)
					close(ch)
					break
				}
			}
		}()

		last, err := p.GetDeviceStatus(ctx, name)
		if err != nil {
			// All device/VM lookups (via lookupVM and the map lookups) wrap
			// ErrNotFound with %w, so errors.Is detects a missing device.
			if errors.Is(err, ErrNotFound) {
				ch <- DeviceStatusUnknown
			}
			return
		}
		ch <- last

		ticker := time.NewTicker(proxmoxStatusPollPeriod)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st, err := p.GetDeviceStatus(ctx, name)
				if err != nil {
					// Same reasoning as the initial read above: a device torn
					// down while being watched must produce a terminal status
					// and close the channel, or the poll loop spins on the
					// missing VM until ctx.Done() (which may be a long time,
					// or never, for a long-lived watcher).
					if errors.Is(err, ErrNotFound) {
						ch <- DeviceStatusUnknown
						return
					}
					continue
				}
				if st != last {
					last = st
					ch <- st
				}
			}
		}
	}()

	return ch
}

// ListDevices returns the names of all devices created by this provider.
func (p *ProxmoxProvider) ListDevices(ctx context.Context) ([]string, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	var devices []string
	for devName := range p.devices {
		devices = append(devices, devName)
	}
	return devices, nil
}

// TeardownAll removes all VMs and SDN networks created by this provider.
func (p *ProxmoxProvider) TeardownAll(ctx context.Context) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	var errs []error
	for name, dev := range p.devices {
		if err := p.destroyDevice(ctx, log, dev); err != nil {
			errs = append(errs, err)
			continue
		}
		delete(p.devices, name)
	}
	p.teardownUnusedNetworks(ctx, log)
	return errors.Join(errs...)
}

// ReconfigureDeviceDisks updates the disk list of a stopped VM in place by
// removing the disks that are no longer in newDisks (matched by image path) and
// re-pointing the boot order at the first remaining disk. It does NOT re-import
// the kept disks, so data written to them (e.g. EVE installed by the installer
// VM) is preserved. newDisks must be a subset of the current disk list.
//
// This backs the installer two-step: the device is set up with
// [installer, target] and, after EVE is written onto the imported target disk,
// reconfigured to [target] -- which detaches/removes the installer disk and
// boots the target.
func (p *ProxmoxProvider) ReconfigureDeviceDisks(
	ctx context.Context, name string, newDisks []DiskImage) error {
	log := logger.FromContext(ctx)
	p.mutex.Lock()
	defer p.mutex.Unlock()

	dev, vm, err := p.lookupVM(ctx, name)
	if err != nil {
		return err
	}
	if mapProxmoxStatus(vm.Status, vm.QMPStatus, log) == DeviceStatusRunning {
		err = fmt.Errorf("device %q is running; stop it before reconfiguring disks", name)
		return err
	}

	// Detach and remove the dropped disks; PVE keeps the remaining disks on their
	// original virtioN slots.
	firstKept := -1
	for i, old := range dev.spec.Disks {
		if generics.ContainsItem(newDisks, old) {
			if firstKept < 0 {
				firstKept = i
			}
			continue
		}
		task, err := vm.UnlinkDisk(ctx, fmt.Sprintf("virtio%d", i), true)
		if err != nil {
			return fmt.Errorf("failed to detach disk virtio%d from device %q: %w",
				i, name, err)
		}
		if err := waitTask(ctx, task); err != nil {
			return fmt.Errorf("failed waiting for detach of disk virtio%d: %w", i, err)
		}
	}
	if firstKept < 0 {
		return fmt.Errorf("device %q: no disks remain after reconfigure", name)
	}

	// Boot from the first remaining disk.
	task, err := vm.Config(ctx, proxmox.VirtualMachineOption{
		Name: "boot", Value: fmt.Sprintf("order=virtio%d", firstKept),
	})
	if err != nil {
		return fmt.Errorf("failed to set boot order for device %q: %w", name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		err = fmt.Errorf("failed waiting for boot-order update of device %q: %w",
			name, err)
		return err
	}

	dev.spec.Disks = newDisks
	log.Infof("Reconfigured disks for device %q: kept %d disk(s), boot=virtio%d",
		name, len(newDisks), firstKept)
	return nil
}

// Close releases resources associated with the provider.
func (p *ProxmoxProvider) Close() error {
	return nil
}

// --------- helpers ---------

// lookupVM returns the device and a fresh VirtualMachine handle.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) lookupVM(
	ctx context.Context, name string) (*proxmoxDevice, *proxmox.VirtualMachine, error) {
	dev, ok := p.devices[name]
	if !ok {
		return nil, nil, fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
	}
	node, err := p.client.Node(ctx, p.conf.Node)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get Proxmox node %q: %w", p.conf.Node, err)
	}
	vm, err := node.VirtualMachine(ctx, dev.vmID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get VM %d for device %q: %w",
			dev.vmID, name, err)
	}
	return dev, vm, nil
}

// destroyDevice stops the VM (if running) and deletes it.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) destroyDevice(
	ctx context.Context, log *logrus.Entry, dev *proxmoxDevice) error {
	p.stopConsoleLogger(dev)

	node, err := p.client.Node(ctx, p.conf.Node)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox node %q: %w", p.conf.Node, err)
	}
	vm, err := node.VirtualMachine(ctx, dev.vmID)
	if err != nil {
		// VM already gone; still remove any uploaded firmware volumes.
		log.Warnf("VM %d for device %q not found during teardown: %v",
			dev.vmID, dev.name, err)
		p.deleteImportVolumes(ctx, log, node, dev.firmwareVolIDs)
		return nil
	}
	if mapProxmoxStatus(vm.Status, vm.QMPStatus, log) == DeviceStatusRunning {
		task, err := vm.Stop(ctx)
		if err != nil {
			return fmt.Errorf("failed to stop VM %d during teardown: %w", dev.vmID, err)
		}
		if err := waitTask(ctx, task); err != nil {
			return fmt.Errorf("failed waiting for VM %d stop during teardown: %w",
				dev.vmID, err)
		}
	}
	task, err := vm.Delete(ctx, &proxmox.VirtualMachineDeleteOptions{
		Purge:                    true,
		DestroyUnreferencedDisks: true,
	})
	if err != nil {
		return fmt.Errorf("failed to delete VM %d for device %q: %w",
			dev.vmID, dev.name, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for VM %d deletion: %w", dev.vmID, err)
	}
	// Remove the uploaded custom-firmware volumes now that the VM is gone.
	p.deleteImportVolumes(ctx, log, node, dev.firmwareVolIDs)
	log.Infof("Removed Proxmox VM %d for device %q", dev.vmID, dev.name)
	return nil
}

// buildVMOptions builds the full set of VirtualMachineOption used to create the
// VM in a powered-off state.
func (p *ProxmoxProvider) buildVMOptions(dev *proxmoxDevice, diskRefs []string,
	firmwareArgs string) ([]proxmox.VirtualMachineOption, error) {
	spec := dev.spec
	memMiB := spec.MemoryBytes >> 20
	cpus := spec.CPUs
	if cpus == 0 {
		cpus = 1
	}

	options := []proxmox.VirtualMachineOption{
		{Name: "name", Value: prefixedName(dev.name)},
		{Name: "cores", Value: int(cpus)},
		{Name: "memory", Value: int(memMiB)},
		{Name: "cpu", Value: "host"},
		{Name: "machine", Value: "q35"},
		{Name: "ostype", Value: "l26"},
		{Name: "scsihw", Value: "virtio-scsi-single"},
		// Expose a serial port for the console (consumed via termproxy) and an
		// enabled guest-agent channel.
		{Name: "serial0", Value: "socket"},
		{Name: "agent", Value: "1"},
		// Make the serial port the primary display, removing PVE's default VGA
		// device entirely (closest equivalent to qemu/libvirt's -nographic).
		// EVE/SDN images are LinuxKit-based with "console=ttyS0" only in their
		// kernel cmdline; with a VGA device also present, they hang very early in
		// boot (confirmed via QMP screendump: frozen at "Booting the kernel.",
		// near-0% guest CPU usage) instead of ever reaching ttyS0 output.
		{Name: "vga", Value: "serial0"},
		// Host hookscript that enables link-local L2 forwarding on xconnect
		// bridges at VM post-start (see proxmoxHookscriptVolID).
		{Name: "hookscript", Value: proxmoxHookscriptVolID},
	}

	// Set speed=1000 and duplex=full on all virtio-net NICs so the guest's
	// MII/bonding subsystem can determine link status.
	extraArgs := "-global virtio-net-pci.speed=1000 -global virtio-net-pci.duplex=full"

	// UEFI (OVMF) boot with the broker-supplied firmware. A non-empty
	// UEFIFirmwareDirPath signals UEFI boot. Proxmox's efidisk0 only manages the
	// EFI vars (not a custom CODE binary), so to boot the exact OVMF the broker
	// built (matching qemu/libvirt for measured-boot/attestation fidelity) we
	// disable PVE's OVMF (bios=seabios, no efidisk0) and attach the uploaded
	// CODE/VARS files as QEMU pflash via args. See uploadFirmware.
	if firmwareArgs != "" {
		extraArgs = firmwareArgs + " " + extraArgs
		options = append(options,
			proxmox.VirtualMachineOption{Name: "bios", Value: "seabios"},
		)
	}

	options = append(options, proxmox.VirtualMachineOption{Name: "args", Value: extraArgs})

	// TPM.
	if spec.WithTPM {
		options = append(options, proxmox.VirtualMachineOption{
			Name:  "tpmstate0",
			Value: fmt.Sprintf("%s:0,version=v2.0", p.conf.Storage),
		})
	}

	// SMBIOS system serial number.
	if spec.SerialNumber != "" {
		enc := base64.StdEncoding.EncodeToString([]byte(spec.SerialNumber))
		options = append(options, proxmox.VirtualMachineOption{
			Name:  "smbios1",
			Value: fmt.Sprintf("serial=%s,base64=1", enc),
		})
	}

	// Disks, imported from the images uploaded to the import storage.
	options = append(options, diskOptions(p.conf.Storage, diskRefs)...)
	if len(diskRefs) > 0 {
		options = append(options, proxmox.VirtualMachineOption{
			Name: "boot", Value: "order=virtio0",
		})
	}

	// Network interfaces, attached to their SDN VNets (bridges). PVE advertises
	// the attached bridge's own MTU to the guest's virtio-net driver via
	// VIRTIO_NET_F_MTU, which then hard-caps any MTU the guest tries to
	// configure on that NIC -- so the evetest SDN zone's VNet bridges are
	// created with a high MTU (see deploy/proxmox/installer.sh.tmpl) rather
	// than needing a per-interface override here.
	for _, iface := range dev.ifaces {
		options = append(options, proxmox.VirtualMachineOption{
			Name: iface.model,
			Value: fmt.Sprintf("virtio=%s,bridge=%s",
				strings.ToUpper(iface.mac.String()), iface.vnet),
		})
	}

	return options, nil
}

// diskOptions builds the virtioN disk options, each importing its data from a
// previously-uploaded import-storage volume into the target storage.
func diskOptions(storage string, diskRefs []string) []proxmox.VirtualMachineOption {
	options := make([]proxmox.VirtualMachineOption, 0, len(diskRefs))
	for i, ref := range diskRefs {
		options = append(options, proxmox.VirtualMachineOption{
			Name:  fmt.Sprintf("virtio%d", i),
			Value: fmt.Sprintf("%s:0,import-from=%s", storage, ref),
		})
	}
	return options
}

// uploadDiskImages uploads each disk image to the import storage and returns the
// resulting import-storage volume IDs, in disk order. Each volume ID serves both
// as the import-from reference when creating the VM and as the cleanup target
// afterwards. The caller must hold p.mutex.
func (p *ProxmoxProvider) uploadDiskImages(ctx context.Context, node *proxmox.Node,
	dev *proxmoxDevice) (volIDs []string, err error) {
	if len(dev.spec.Disks) == 0 {
		return nil, nil
	}
	storage, err := node.Storage(ctx, p.conf.ImportStorage)
	if err != nil {
		return nil, fmt.Errorf("failed to get import storage %q: %w",
			p.conf.ImportStorage, err)
	}
	for i, disk := range dev.spec.Disks {
		path, err := utils.ResolveFile(disk.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve disk image path %q: %w",
				disk.Path, err)
		}
		ext := "qcow2"
		if disk.Format == DiskImageFormatRaw {
			ext = "raw"
		}
		uploadName := fmt.Sprintf("%s-%d.%s", prefixedName(dev.name), i, ext)
		task, err := storage.UploadWithName("import", path, uploadName)
		if err != nil {
			return nil, fmt.Errorf("failed to upload disk image %q to storage %q: %w",
				path, p.conf.ImportStorage, err)
		}
		if err := waitTask(ctx, task); err != nil {
			return nil, fmt.Errorf("failed waiting for upload of disk image %q: %w",
				path, err)
		}
		volID := fmt.Sprintf("%s:import/%s", p.conf.ImportStorage, uploadName)
		volIDs = append(volIDs, volID)
	}
	return volIDs, nil
}

// deleteImportVolumes removes uploaded import-storage volumes (best-effort).
func (p *ProxmoxProvider) deleteImportVolumes(ctx context.Context, log *logrus.Entry,
	node *proxmox.Node, volIDs []string) {
	if len(volIDs) == 0 {
		return
	}
	storage, err := node.Storage(ctx, p.conf.ImportStorage)
	if err != nil {
		log.Warnf("failed to get import storage %q for cleanup: %v",
			p.conf.ImportStorage, err)
		return
	}
	for _, volID := range volIDs {
		task, err := storage.DeleteContent(ctx, volID)
		if err != nil {
			log.Warnf("failed to delete uploaded import volume %q: %v", volID, err)
			continue
		}
		if err := waitTask(ctx, task); err != nil {
			log.Warnf("failed waiting for deletion of import volume %q: %v", volID, err)
		}
	}
}

// uploadFirmware uploads the device's custom OVMF CODE and VARS files
// (OVMF_CODE.fd / OVMF_VARS.fd from UEFIFirmwareDirPath) to the import storage
// and returns the QEMU pflash "args" string referencing them by their on-host
// paths. It records the uploaded volume IDs on the device for removal at
// teardown. Returns an empty args string when the device does not use custom
// UEFI firmware. The caller must hold p.mutex.
//
// The files are uploaded with a ".raw" name (they are raw pflash images) so the
// import-content validator accepts them. Unlike disk images -- which import-from
// copies into the VM disk during creation -- these files are opened live by QEMU
// on every boot, so they must persist for the VM's lifetime; the VARS file is
// per-VM and writable.
func (p *ProxmoxProvider) uploadFirmware(ctx context.Context, node *proxmox.Node,
	dev *proxmoxDevice) (string, error) {
	if dev.spec.UEFIFirmwareDirPath == "" {
		return "", nil
	}
	codeSrc, err := utils.ResolveFile(
		filepath.Join(dev.spec.UEFIFirmwareDirPath, "OVMF_CODE.fd"))
	if err != nil {
		return "", fmt.Errorf("failed to resolve OVMF_CODE.fd: %w", err)
	}
	varsSrc, err := utils.ResolveFile(
		filepath.Join(dev.spec.UEFIFirmwareDirPath, "OVMF_VARS.fd"))
	if err != nil {
		return "", fmt.Errorf("failed to resolve OVMF_VARS.fd: %w", err)
	}

	basePath, err := p.importStoragePath(ctx)
	if err != nil {
		return "", err
	}
	storage, err := node.Storage(ctx, p.conf.ImportStorage)
	if err != nil {
		return "", fmt.Errorf("failed to get import storage %q: %w",
			p.conf.ImportStorage, err)
	}

	codeName := fmt.Sprintf("%s-OVMF_CODE.raw", prefixedName(dev.name))
	varsName := fmt.Sprintf("%s-OVMF_VARS.raw", prefixedName(dev.name))
	for _, up := range []struct{ src, name string }{
		{codeSrc, codeName},
		{varsSrc, varsName},
	} {
		task, err := storage.UploadWithName("import", up.src, up.name)
		if err != nil {
			return "", fmt.Errorf("failed to upload firmware %q to storage %q: %w",
				up.src, p.conf.ImportStorage, err)
		}
		if err := waitTask(ctx, task); err != nil {
			return "", fmt.Errorf("failed waiting for firmware upload of %q: %w",
				up.src, err)
		}
		dev.firmwareVolIDs = append(dev.firmwareVolIDs,
			fmt.Sprintf("%s:import/%s", p.conf.ImportStorage, up.name))
	}

	// unit=0 = read-only CODE, unit=1 = writable per-VM VARS.
	args := fmt.Sprintf(
		"-drive if=pflash,unit=0,format=raw,readonly=on,file=%s "+
			"-drive if=pflash,unit=1,format=raw,file=%s",
		filepath.Join(basePath, "import", codeName),
		filepath.Join(basePath, "import", varsName))
	return args, nil
}

// importStoragePath returns the absolute on-host directory path of the import
// storage, required to reference uploaded files by path (e.g. for pflash args).
// Only directory-backed storages expose such a path.
func (p *ProxmoxProvider) importStoragePath(ctx context.Context) (string, error) {
	cs, err := p.client.ClusterStorage(ctx, p.conf.ImportStorage)
	if err != nil {
		return "", fmt.Errorf("failed to get storage config for %q: %w",
			p.conf.ImportStorage, err)
	}
	if cs.Path == "" {
		return "", fmt.Errorf(
			"import storage %q has no filesystem path; a directory-backed storage "+
				"is required for custom UEFI firmware", p.conf.ImportStorage)
	}
	return cs.Path, nil
}

// ensureUplinkNetwork resolves the (externally managed) uplink SDN VNet and
// verifies it exists.
//
// The uplink VNet and its subnet(s) are created by the Proxmox broker
// installer, NOT by this provider: the always-running broker VM is attached
// to it, so the provider must never create it nor (in teardownUnusedNetworks)
// delete it. The uplink network is therefore not tracked in p.networks.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) ensureUplinkNetwork(
	ctx context.Context) (*proxmoxNetwork, error) {
	vnet := uplinkNetwork

	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get Proxmox cluster: %w", err)
	}
	if _, err := cluster.SDNVNet(ctx, vnet); err != nil {
		return nil, fmt.Errorf("uplink VNet %q not found; the Proxmox broker "+
			"installer must pre-create the SDN uplink network: %w", vnet, err)
	}
	return &proxmoxNetwork{name: vnet, vnet: vnet, isUplink: true}, nil
}

// ensureXConnectNetwork ensures an isolated SDN VNet (no subnet) for a
// point-to-point link exists.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) ensureXConnectNetwork(
	ctx context.Context, log *logrus.Entry, netName string,
	changed *bool) (*proxmoxNetwork, error) {
	if network, ok := p.networks[netName]; ok {
		return network, nil
	}
	if err := p.ensureZone(ctx, log, changed); err != nil {
		return nil, err
	}
	if err := p.createVNet(ctx, netName, changed); err != nil {
		return nil, err
	}
	network := &proxmoxNetwork{name: netName, vnet: netName, isUplink: false}
	p.networks[netName] = network
	return network, nil
}

// ensureZone creates the evetest SDN simple zone if it does not already exist.
func (p *ProxmoxProvider) ensureZone(
	ctx context.Context, log *logrus.Entry, changed *bool) error {
	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox cluster: %w", err)
	}
	if _, err := cluster.SDNZone(ctx, sdnZone); err == nil {
		return nil // zone already exists
	}
	if err := cluster.NewSDNZone(ctx, &proxmox.SDNZoneOptions{
		Name: sdnZone,
		Type: "simple",
		IPAM: "pve",
		DHCP: "dnsmasq",
	}); err != nil {
		return fmt.Errorf("failed to create SDN zone %q: %w", sdnZone, err)
	}
	*changed = true
	log.Infof("Created SDN zone %q", sdnZone)
	return nil
}

// createVNet creates an SDN VNet in the evetest zone.
func (p *ProxmoxProvider) createVNet(
	ctx context.Context, vnet string, changed *bool) error {
	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox cluster: %w", err)
	}
	if _, err := cluster.SDNVNet(ctx, vnet); err == nil {
		return nil // already exists
	}
	opts := &proxmox.VNetOptions{
		Name: vnet,
		Zone: sdnZone,
		Type: "vnet",
	}
	if err := cluster.NewSDNVNet(ctx, opts); err != nil {
		return fmt.Errorf("failed to create SDN VNet %q: %w", vnet, err)
	}
	*changed = true
	return nil
}

// applySDN applies pending SDN configuration changes cluster-wide and waits for
// the resulting task to complete.
func (p *ProxmoxProvider) applySDN(ctx context.Context, log *logrus.Entry) error {
	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox cluster: %w", err)
	}
	task, err := cluster.SDNApply(ctx)
	if err != nil {
		return fmt.Errorf("failed to apply SDN configuration: %w", err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for SDN apply: %w", err)
	}
	return nil
}

// teardownUnusedNetworks deletes SDN VNets no longer referenced by any device.
// The evetest zone is left in place. The caller must hold p.mutex.
func (p *ProxmoxProvider) teardownUnusedNetworks(ctx context.Context, log *logrus.Entry) {
	inUse := make(map[string]bool)
	for _, dev := range p.devices {
		for _, iface := range dev.ifaces {
			inUse[iface.netName] = true
		}
	}
	cluster, err := p.client.Cluster(ctx)
	if err != nil {
		log.Warnf("failed to get Proxmox cluster for network GC: %v", err)
		return
	}
	changed := false
	for netName, network := range p.networks {
		// Uplink VNets are externally managed (installer-owned) and are never
		// tracked here, but guard defensively: never delete them.
		if network.isUplink || inUse[netName] {
			continue
		}
		if err := cluster.DeleteSDNVNet(ctx, network.vnet); err != nil {
			log.Warnf("failed to delete SDN VNet %q: %v", network.vnet, err)
			continue
		}
		delete(p.networks, netName)
		changed = true
	}
	if changed {
		if err := p.applySDN(ctx, log); err != nil {
			log.Warnf("failed to apply SDN after network GC: %v", err)
		}
	}
}

// updateDeviceStatus records the device status and notifies watchers. The caller
// must hold p.mutex.
func (p *ProxmoxProvider) updateDeviceStatus(dev *proxmoxDevice, status DeviceStatus) {
	dev.status = status
	for _, ch := range p.watchers[dev.name] {
		select {
		case ch <- status:
		default:
		}
	}
}

// getDeviceConsoleLogFile returns the filesystem path for storing the console log
// for a given device name.
func (p *ProxmoxProvider) getDeviceConsoleLogFile(name string) string {
	return filepath.Join(os.TempDir(),
		"evetest-proxmox-consoles",
		fmt.Sprintf("%s.log", name))
}

// startConsoleLogger opens a serial console session and copies its output into
// the device console log file, reconnecting on any error other than the
// logger's own context being cancelled -- the console connection can drop for
// reasons unrelated to the VM's health (e.g. a termproxy session timeout), and
// should not silently stop logging for the rest of the device's lifetime.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) startConsoleLogger(ctx context.Context, dev *proxmoxDevice) {
	if dev.consoleCancel != nil {
		return // already running
	}
	log := logger.FromContext(ctx)
	loggerCtx, cancel := context.WithCancel(context.Background())
	loggerCtx = logger.WithLogger(loggerCtx, log)
	dev.consoleCancel = cancel
	done := make(chan struct{})
	dev.consoleDone = done
	vmID := dev.vmID
	logPath := dev.consoleLog
	mux := dev.consoleMux
	node := p.conf.Node
	client := p.client

	go func() {
		defer close(done)
		const retryInterval = 2 * time.Second
		for loggerCtx.Err() == nil {
			err := runConsoleLogger(loggerCtx, client, node, vmID, logPath, mux)
			if err != nil {
				log.Warnf("Console logger for VM %d stopped (will retry): %v", vmID, err)
			}
			select {
			case <-loggerCtx.Done():
				return
			case <-time.After(retryInterval):
			}
		}
	}()
}

// runConsoleLogger opens one serial console session for vmID, copies its
// output into logPath, and publishes the connection into mux so it can be
// shared with any interactively attached client (see AttachToDeviceConsole),
// until ctx is cancelled or the connection breaks.
func runConsoleLogger(
	ctx context.Context, client *proxmox.Client, node string, vmID int, logPath string,
	mux *consoleMux) error {
	n, err := client.Node(ctx, node)
	if err != nil {
		return err
	}
	vm, err := n.VirtualMachine(ctx, vmID)
	if err != nil {
		return err
	}
	conn, err := openSerialConsole(vm)
	if err != nil {
		return err
	}
	// wsConsole.Close() is not safe to call twice (the underlying library
	// panics on a double channel-close), and both the ctx watcher below and
	// the plain defer may try to close it, so guard with sync.Once.
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	defer closeConn()

	mux.setConn(conn)
	defer mux.setConn(nil)

	// conn.Read() below only unblocks when the underlying websocket connection
	// itself breaks; it has no idea about ctx. Force-close the connection as
	// soon as ctx is cancelled so a Read blocked on an idle console doesn't
	// keep this goroutine (and the connection) alive past shutdown.
	watchDone := make(chan struct{})
	defer close(watchDone)
	go func() {
		select {
		case <-ctx.Done():
			closeConn()
		case <-watchDone:
		}
	}()

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 4096)
	for {
		nr, err := conn.Read(buf)
		if nr > 0 {
			_, _ = f.Write(buf[:nr])
			mux.broadcast(buf[:nr])
		}
		if err != nil {
			if ctx.Err() != nil {
				return nil // clean shutdown, not a real failure
			}
			return err
		}
	}
}

// stopConsoleLogger stops the background console logger and blocks until its
// goroutine has fully exited, so callers can safely start a new one right
// after without briefly running two against the same VM.
// The caller must hold p.mutex.
func (p *ProxmoxProvider) stopConsoleLogger(dev *proxmoxDevice) {
	if dev.consoleCancel != nil {
		dev.consoleCancel()
		dev.consoleCancel = nil
		<-dev.consoleDone
		dev.consoleDone = nil
	}
}

// mapProxmoxStatus maps the Proxmox VM status / QMP status to a DeviceStatus.
func mapProxmoxStatus(status, qmpStatus string, log *logrus.Entry) DeviceStatus {
	switch status {
	case "running":
		if qmpStatus == "paused" || qmpStatus == "prelaunch" {
			return DeviceStatusSuspended
		}
		return DeviceStatusRunning
	case "stopped":
		return DeviceStatusStopped
	case "paused":
		return DeviceStatusSuspended
	default:
		log.Debugf("unknown Proxmox VM status %q (qmp %q)", status, qmpStatus)
		return DeviceStatusUnknown
	}
}

// consoleMux fans out a single underlying console connection (held by the
// background logger, see startConsoleLogger) to any number of interactively
// attached readers/writers (AttachToDeviceConsole), instead of each opening
// its own competing termproxy session.
type consoleMux struct {
	mu   sync.Mutex
	conn io.ReadWriteCloser // set while a connection is live; nil otherwise
	subs map[chan []byte]struct{}
}

func newConsoleMux() *consoleMux {
	return &consoleMux{subs: make(map[chan []byte]struct{})}
}

// setConn sets the shared connection. Passing nil also closes every current
// subscriber's channel (ending their Read with io.EOF) so a dropped
// connection doesn't leave them blocked on it forever.
func (m *consoleMux) setConn(conn io.ReadWriteCloser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.conn = conn
	if conn == nil {
		for ch := range m.subs {
			close(ch)
		}
		m.subs = make(map[chan []byte]struct{})
	}
}

// broadcast delivers b to every subscriber. Slow or absent subscribers are
// dropped rather than allowed to stall the shared connection's read loop.
func (m *consoleMux) broadcast(b []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ch := range m.subs {
		select {
		case ch <- append([]byte(nil), b...):
		default:
		}
	}
}

func (m *consoleMux) write(p []byte) (int, error) {
	m.mu.Lock()
	conn := m.conn
	m.mu.Unlock()
	if conn == nil {
		return 0, errors.New("console is not connected")
	}
	return conn.Write(p)
}

func (m *consoleMux) subscribe() *muxSubscriber {
	ch := make(chan []byte, 32)
	m.mu.Lock()
	m.subs[ch] = struct{}{}
	m.mu.Unlock()
	return &muxSubscriber{mux: m, ch: ch}
}

func (m *consoleMux) unsubscribe(ch chan []byte) {
	m.mu.Lock()
	_, ok := m.subs[ch]
	delete(m.subs, ch)
	m.mu.Unlock()
	if ok {
		close(ch)
	}
}

// muxSubscriber is an io.ReadWriteCloser handed to an interactively attached
// client: reads come from the mux's broadcast, writes go directly to the
// mux's shared underlying connection, and Close only unsubscribes (it must
// not close the underlying connection, which the background logger still
// needs).
type muxSubscriber struct {
	mux     *consoleMux
	ch      chan []byte
	readBuf []byte
}

func (s *muxSubscriber) Read(p []byte) (int, error) {
	if len(s.readBuf) == 0 {
		b, ok := <-s.ch
		if !ok {
			return 0, io.EOF
		}
		s.readBuf = b
	}
	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

func (s *muxSubscriber) Write(p []byte) (int, error) {
	return s.mux.write(p)
}

func (s *muxSubscriber) Close() error {
	s.mux.unsubscribe(s.ch)
	return nil
}

// openSerialConsole opens a Proxmox termproxy session to the VM serial console
// and returns it as an io.ReadWriteCloser.
func openSerialConsole(vm *proxmox.VirtualMachine) (io.ReadWriteCloser, error) {
	term, err := vm.TermProxy(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to open termproxy for VM %d: %w", vm.VMID, err)
	}
	send, recv, errs, closer, err := vm.TermWebSocket(term)
	if err != nil {
		err = fmt.Errorf("failed to open console websocket for VM %d: %w", vm.VMID, err)
		return nil, err
	}
	return &wsConsole{
		send: send, recv: recv, errs: errs, closer: closer,
		closing: make(chan struct{}),
	}, nil
}

// wsConsole adapts the go-proxmox terminal websocket channels to an
// io.ReadWriteCloser.
type wsConsole struct {
	send    chan []byte
	recv    chan []byte
	errs    chan error
	closer  func() error
	readBuf []byte

	// closeMu serializes Write against Close: go-proxmox closes send/recv/errs
	// from inside Close, and would panic if that raced a concurrent Write, so
	// Close only proceeds once every in-flight Write has returned, and any Write
	// started after Close begins bails out immediately instead of touching the
	// channels. closing is closed by Close before it even tries to acquire the
	// lock, so a Write already blocked in its select wakes up immediately
	// instead of Close having to wait on it indefinitely.
	closeMu   sync.RWMutex
	closed    bool
	closing   chan struct{}
	closeOnce sync.Once
}

func (w *wsConsole) Read(p []byte) (int, error) {
	if len(w.readBuf) == 0 {
		select {
		case b, ok := <-w.recv:
			if !ok {
				return 0, io.EOF
			}
			w.readBuf = b
		case err := <-w.errs:
			if err == nil {
				err = io.EOF
			}
			return 0, err
		}
	}
	n := copy(p, w.readBuf)
	w.readBuf = w.readBuf[n:]
	return n, nil
}

func (w *wsConsole) Write(p []byte) (int, error) {
	w.closeMu.RLock()
	defer w.closeMu.RUnlock()
	if w.closed {
		return 0, io.ErrClosedPipe
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case w.send <- b:
		return len(p), nil
	case err := <-w.errs:
		if err == nil {
			err = io.ErrClosedPipe
		}
		return 0, err
	case <-w.closing:
		return 0, io.ErrClosedPipe
	}
}

func (w *wsConsole) Close() error {
	w.closeOnce.Do(func() { close(w.closing) })
	w.closeMu.Lock()
	defer w.closeMu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.closer != nil {
		return w.closer()
	}
	return nil
}
