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

	"github.com/zededa/ghw/internal/config"
	"github.com/zededa/ghw/pkg/accelerator"
	"github.com/zededa/ghw/pkg/baseboard"
	"github.com/zededa/ghw/pkg/bios"
	"github.com/zededa/ghw/pkg/block"
	"github.com/zededa/ghw/pkg/can"
	"github.com/zededa/ghw/pkg/chassis"
	"github.com/zededa/ghw/pkg/cpu"
	"github.com/zededa/ghw/pkg/gpu"
	"github.com/zededa/ghw/pkg/marshal"
	"github.com/zededa/ghw/pkg/memory"
	"github.com/zededa/ghw/pkg/net"
	"github.com/zededa/ghw/pkg/pci"
	"github.com/zededa/ghw/pkg/product"
	"github.com/zededa/ghw/pkg/serial"
	"github.com/zededa/ghw/pkg/topology"
	"github.com/zededa/ghw/pkg/tpm"
	"github.com/zededa/ghw/pkg/usb"
	"github.com/zededa/ghw/pkg/watchdog"
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
	Watchdog    *watchdog.Info    `json:"watchdog"`
	TPM         *tpm.Info         `json:"tpm"`
	Serial      *serial.Info      `json:"serial"`
	CAN         *can.Info         `json:"can"`
	StatusLED   bool              `json:"status_led"`
}

// Host returns a pointer to a HostInfo struct that contains fields with
// information about the host system's CPU, memory, network devices, etc
func Host(args ...any) (*HostInfo, error) {
	ctx := config.ContextFromArgs(args...)
	memInfo, err := memory.New(ctx)
	if err != nil {
		return nil, err
	}
	blockInfo, err := block.New(ctx)
	if err != nil {
		return nil, err
	}
	cpuInfo, err := cpu.New(ctx)
	if err != nil {
		return nil, err
	}
	topologyInfo, err := topology.New(ctx)
	if err != nil {
		return nil, err
	}
	netInfo, err := net.New(ctx)
	if err != nil {
		return nil, err
	}
	gpuInfo, err := gpu.New(ctx)
	if err != nil {
		return nil, err
	}
	acceleratorInfo, err := accelerator.New(ctx)
	if err != nil {
		return nil, err
	}
	chassisInfo, err := chassis.New(ctx)
	if err != nil {
		return nil, err
	}
	biosInfo, err := bios.New(ctx)
	if err != nil {
		return nil, err
	}
	baseboardInfo, err := baseboard.New(ctx)
	if err != nil {
		return nil, err
	}
	productInfo, err := product.New(ctx)
	if err != nil {
		return nil, err
	}
	pciInfo, err := pci.New(ctx)
	if err != nil {
		return nil, err
	}
	usbInfo, err := usb.New(ctx)
	if err != nil {
		return nil, err
	}
	watchdogInfo, err := watchdog.New(ctx)
	if err != nil {
		return nil, err
	}
	tpmInfo, err := tpm.New(ctx)
	if err != nil {
		return nil, err
	}
	serialInfo, err := serial.New(ctx)
	if err != nil {
		return nil, err
	}
	canInfo, err := can.New(ctx)
	if err != nil {
		return nil, err
	}

	// Simple check for LEDs
	statusLED := false
	if entries, err := os.ReadDir(filepath.Join(config.Chroot(ctx), "sys", "class", "leds")); err == nil && len(entries) > 0 {
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
		Watchdog:    watchdogInfo,
		TPM:         tpmInfo,
		Serial:      serialInfo,
		CAN:         canInfo,
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
		info.Watchdog.String(),
		info.TPM.String(),
		info.Serial.String(),
		info.CAN.String(),
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
