//
// Use and distribution licensed under the Apache license version 2.
//
// See the COPYING file in the root project directory for full text.
//

package ghw

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jaypipes/ghw/pkg/accelerator"
	"github.com/jaypipes/ghw/pkg/baseboard"
	"github.com/jaypipes/ghw/pkg/bios"
	"github.com/jaypipes/ghw/pkg/block"
	"github.com/jaypipes/ghw/pkg/can"
	"github.com/jaypipes/ghw/pkg/chassis"
	"github.com/jaypipes/ghw/pkg/cpu"
	"github.com/jaypipes/ghw/pkg/gpu"
	"github.com/jaypipes/ghw/pkg/marshal"
	"github.com/jaypipes/ghw/pkg/memory"
	"github.com/jaypipes/ghw/pkg/net"
	"github.com/jaypipes/ghw/pkg/option"
	"github.com/jaypipes/ghw/pkg/pci"
	"github.com/jaypipes/ghw/pkg/product"
	"github.com/jaypipes/ghw/pkg/serial"
	"github.com/jaypipes/ghw/pkg/topology"
	"github.com/jaypipes/ghw/pkg/tpm"
	"github.com/jaypipes/ghw/pkg/usb"
	"github.com/jaypipes/ghw/pkg/watchdog"
)

// HostInfo is a wrapper struct containing information about the host system's
// memory, block storage, CPU, etc
type HostInfo struct {
	Memory      *memory.Info      `json:"memory"`
	Block       *block.Info       `json:"block"`
	CPU         *cpu.Info         `json:"cpu"`
	Topology    *topology.Info    `json:"topology"`
	Network     *net.Info         `json:"network"`
	GPU         *gpu.Info         `json:"gpu"`
	Accelerator *accelerator.Info `json:"accelerator"`
	Chassis     *chassis.Info     `json:"chassis"`
	BIOS        *bios.Info        `json:"bios"`
	Baseboard   *baseboard.Info   `json:"baseboard"`
	Product     *product.Info     `json:"product"`
	PCI         *pci.Info         `json:"pci"`
	USB         *usb.Info         `json:"usb"`
	Serial      *serial.Info      `json:"serial"`
	CAN         *can.Info         `json:"can"`
	TPM         *tpm.Info         `json:"tpm"`
	Watchdog    *watchdog.Info    `json:"watchdog"`
	StatusLED   bool              `json:"status_led"`
}

// Host returns a pointer to a HostInfo struct that contains fields with
// information about the host system's CPU, memory, network devices, etc
func Host(opts ...Option) (*HostInfo, error) {
	memInfo, err := memory.New(opts...)
	if err != nil {
		return nil, err
	}
	blockInfo, err := block.New(opts...)
	if err != nil {
		return nil, err
	}
	cpuInfo, err := cpu.New(opts...)
	if err != nil {
		return nil, err
	}
	topologyInfo, err := topology.New(opts...)
	if err != nil {
		return nil, err
	}
	netInfo, err := net.New(opts...)
	if err != nil {
		return nil, err
	}
	gpuInfo, err := gpu.New(opts...)
	if err != nil {
		return nil, err
	}
	acceleratorInfo, err := accelerator.New(opts...)
	if err != nil {
		return nil, err
	}
	chassisInfo, err := chassis.New(opts...)
	if err != nil {
		return nil, err
	}
	biosInfo, err := bios.New(opts...)
	if err != nil {
		return nil, err
	}
	baseboardInfo, err := baseboard.New(opts...)
	if err != nil {
		return nil, err
	}
	productInfo, err := product.New(opts...)
	if err != nil {
		return nil, err
	}
	pciInfo, err := pci.New(opts...)
	if err != nil {
		return nil, err
	}
	usbInfo, err := usb.New(opts...)
	if err != nil {
		return nil, err
	}
	serialInfo, err := serial.New(opts...)
	if err != nil {
		return nil, err
	}
	canInfo, err := can.New(opts...)
	if err != nil {
		return nil, err
	}
	tpmInfo, err := tpm.New(opts...)
	if err != nil {
		return nil, err
	}
	watchdogInfo, err := watchdog.New(opts...)
	if err != nil {
		return nil, err
	}

	// Simple check for LEDs
	statusLED := false
	merged := option.FromEnv()
	for _, opt := range opts {
		opt(merged)
	}

	if entries, err := os.ReadDir(filepath.Join(merged.Chroot, "sys", "class", "leds")); err == nil && len(entries) > 0 {
		statusLED = true
	}

	return &HostInfo{
		CPU:         cpuInfo,
		Memory:      memInfo,
		Block:       blockInfo,
		Topology:    topologyInfo,
		Network:     netInfo,
		GPU:         gpuInfo,
		Accelerator: acceleratorInfo,
		Chassis:     chassisInfo,
		BIOS:        biosInfo,
		Baseboard:   baseboardInfo,
		Product:     productInfo,
		PCI:         pciInfo,
		USB:         usbInfo,
		Serial:      serialInfo,
		CAN:         canInfo,
		TPM:         tpmInfo,
		Watchdog:    watchdogInfo,
		StatusLED:   statusLED,
	}, nil
}

// String returns a newline-separated output of the HostInfo's component
// structs' String-ified output
func (info *HostInfo) String() string {
	return fmt.Sprintf(
		"%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\nStatusLED: %v\n",
		info.Block.String(),
		info.CPU.String(),
		info.GPU.String(),
		info.Accelerator.String(),
		info.Memory.String(),
		info.Network.String(),
		info.Topology.String(),
		info.Chassis.String(),
		info.BIOS.String(),
		info.Baseboard.String(),
		info.Product.String(),
		info.PCI.String(),
		info.USB.String(),
		info.Serial.String(),
		info.CAN.String(),
		info.TPM.String(),
		info.Watchdog.String(),
		info.StatusLED,
	)
}

// YAMLString returns a string with the host information formatted as YAML
// under a top-level "host:" key
func (i *HostInfo) YAMLString() string {
	return marshal.SafeYAML(i)
}

// JSONString returns a string with the host information formatted as JSON
// under a top-level "host:" key
func (i *HostInfo) JSONString(indent bool) string {
	return marshal.SafeJSON(i, indent)
}
