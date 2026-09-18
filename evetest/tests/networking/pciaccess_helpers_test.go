// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package networking_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve/evetest"
	pillartypes "github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"

	// revive:disable:dot-imports
	. "github.com/onsi/gomega"
)

const (
	// pciSysfsCmdTimeout bounds the short host-side commands of this file.
	pciSysfsCmdTimeout = 30 * time.Second

	// bpftraceCompilerDirParamKey names the test parameter with the compiler
	// sources, see bpftraceCompilerDirParam.
	bpftraceCompilerDirParamKey = "BPFTRACE_COMPILER_DIR"

	// pciTracerStartTimeout bounds getting the tracer to run on the device:
	// the compiler builds a VM image around the device's kernel, boots it
	// under QEMU and compiles the script inside, which takes several minutes
	// the first time, when the images still have to be pulled.
	pciTracerStartTimeout = 30 * time.Minute
	// pciTracerRunTimeout is handed to the compiler as the limit of the
	// remote run; a safety net only, as the script exits on the end marker.
	pciTracerRunTimeout = 45 * time.Minute
	// pciTracerFinishTimeout bounds the wait for the tracer to exit and the
	// compiler to hand over its output once the end marker was set.
	pciTracerFinishTimeout = 2 * time.Minute
	// pciTracerAttachDelay is granted to the AOT runtime to attach its
	// probes after the compiler reports having started it.
	pciTracerAttachDelay = 5 * time.Second

	// phaseSelfTest is the tracer phase holding the tracer's own control
	// write; the only phase in which a write-open is expected. phaseEnd is
	// the marker the tracer script exits on.
	phaseSelfTest = "self-test"
	phaseEnd      = "end"

	// pciTracerPhaseDir is a directory that does not exist: mark() opens
	// <pciTracerPhaseDir><phase> to inject a phase marker into the trace.
	// The open fails, but the traced syscall entry carries the path and is
	// recorded in order with the accesses it separates.
	pciTracerPhaseDir = "/sys/bus/pci/evetest-phase/"

	// compilerRemoteAOTPath is where the compiler's run-via-ssh uploads the
	// compiled script on the device, and leaves it after the run.
	compilerRemoteAOTPath = "/tmp/bpf.aot"
	// compilerRunningMarker is the compiler's log line right before it
	// starts the uploaded script on the device.
	compilerRunningMarker = "Running bpftrace program"
	// compilerStderrSeparator precedes the remote stderr in the compiler's
	// output, after the script's own output.
	compilerStderrSeparator = "----"
	// eveSSHKeyPath is the private key the framework uses for SSH into EVE
	// (see ssh.go); the compiler is given the same one.
	eveSSHKeyPath = "/root/.ssh/eve_rsa"

	// pciClassVGAPrefix is the class code prefix of VGA compatible
	// controllers as sysfs prints it.
	pciClassVGAPrefix = "0x0300"

	// openAccessModeMask isolates the access mode from open(2) flags and
	// openReadOnly is the O_RDONLY mode.
	openAccessModeMask = 0x3
	openReadOnly       = 0x0
)

// pciPathPrefixes are the paths through which a host process reaches a PCI
// device: its sysfs attributes, the legacy procfs files and physical memory.
// consolePathPrefixes are the console attach points through which the host
// takes a VGA device's framebuffer for its own console: the framebuffer
// platform drivers' bind and unbind files and the vtconsole bind files. Both
// lists mirror the filter of the tracer scripts in testdata/.
var (
	pciPathPrefixes     = []string{"/sys/bus/pci/", "/sys/devices/pci", "/proc/bus/pci/", "/dev/mem"}
	consolePathPrefixes = []string{"/sys/bus/platform/drivers/", "/sys/class/vtconsole/"}
)

// bpftraceCompilerDirParam is the test parameter naming the sources of
// eve-tools/bpftrace-compiler, whose run-via-ssh command compiles the tracer
// for the device's kernel and runs it there. The default is their location in
// an EVE checkout relative to this test package; make evetest mounts them into
// the container at the same relative position. The compiler keeps compiled
// scripts, keyed by kernel image and script content, in
// ~/.bpftrace-compiler/cache when that directory exists; make evetest persists
// it across runs.
var bpftraceCompilerDirParam = evetest.TestParameterDefinition{
	Key:          bpftraceCompilerDirParamKey,
	DefaultValue: "../../../eve-tools/bpftrace-compiler",
	Description: evetest.TestParameterDescription{
		Summary: "Sources of eve-tools/bpftrace-compiler, which compiles the PCI access tracer of TestVGAPassthroughNoHostAccess for the device's kernel and runs it there; the default is their location in an EVE checkout relative to the test package",
		Default: "../../../eve-tools/bpftrace-compiler",
	},
}

// pciDeviceInfo describes a PCI device as sysfs presents it.
type pciDeviceInfo struct {
	BDF    string // domain:bus:device.function
	Class  string // class code, e.g. 0x030000
	Vendor string // vendor id, e.g. 0x1234
	Device string // device id, e.g. 0x1111
}

// isVGA reports whether the device is a VGA compatible controller.
func (d pciDeviceInfo) isVGA() bool {
	return strings.HasPrefix(d.Class, pciClassVGAPrefix)
}

// sameModel reports whether the device has the same vendor and device id as
// the other, i.e. is the same kind of hardware; the addresses may differ, as
// a guest enumerates a passed-through device at an address of its own.
func (d pciDeviceInfo) sameModel(other pciDeviceInfo) bool {
	return d.Vendor == other.Vendor && d.Device == other.Device
}

func (d pciDeviceInfo) String() string {
	return fmt.Sprintf("%s class %s %s:%s", d.BDF, d.Class,
		strings.TrimPrefix(d.Vendor, "0x"), strings.TrimPrefix(d.Device, "0x"))
}

// listPCIDevicesScript prints one line per PCI device: address, class code,
// vendor id and device id. It works on the EVE host and inside a guest alike,
// as it needs only sysfs.
const listPCIDevicesScript = `for d in /sys/bus/pci/devices/*; do
    printf '%s %s %s %s\n' "$(basename "$d")" "$(cat "$d/class")" "$(cat "$d/vendor")" "$(cat "$d/device")"
done
`

// parsePCIDeviceList parses the output of listPCIDevicesScript.
func parsePCIDeviceList(output string) ([]pciDeviceInfo, error) {
	var devices []pciDeviceInfo
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 4 {
			return nil, fmt.Errorf("unexpected PCI device line %q", line)
		}
		devices = append(devices, pciDeviceInfo{
			BDF: fields[0], Class: fields[1], Vendor: fields[2], Device: fields[3],
		})
	}
	return devices, nil
}

// listPCIDevices returns the PCI devices of the EVE host.
func listPCIDevices(device *evetest.EdgeDevice) ([]pciDeviceInfo, error) {
	stdout, stderr, err := device.RunShellScript(listPCIDevicesScript, pciSysfsCmdTimeout, 0)
	if err != nil {
		return nil, fmt.Errorf("listing PCI devices: %w (stderr: %s)", err, stderr)
	}
	return parsePCIDeviceList(stdout)
}

// findVGADevice returns the first VGA compatible controller of the list, or
// nil when there is none.
func findVGADevice(devices []pciDeviceInfo) *pciDeviceInfo {
	for i := range devices {
		if devices[i].isVGA() {
			return &devices[i]
		}
	}
	return nil
}

// hasVGADeviceOfModel reports whether the list holds a VGA compatible
// controller of the same model as the given device.
func hasVGADeviceOfModel(devices []pciDeviceInfo, model pciDeviceInfo) bool {
	for _, d := range devices {
		if d.isVGA() && d.sameModel(model) {
			return true
		}
	}
	return false
}

// formatPCIDevices renders the devices one per line for a log or failure
// message.
func formatPCIDevices(devices []pciDeviceInfo) string {
	lines := make([]string, 0, len(devices))
	for _, d := range devices {
		lines = append(lines, "  "+d.String())
	}
	return strings.Join(lines, "\n")
}

// readAssignableAdapter returns pillar's I/O bundle for the given physical
// label, read from domainmgr's AssignableAdapters publication. It is the only
// place the PCI address of an adapter is available, as the device info API
// reports adapters by MAC address only.
func readAssignableAdapter(device *evetest.EdgeDevice,
	phylabel string) (pillartypes.IoBundle, error) {
	var aa pillartypes.AssignableAdapters
	err := evetest.ReadPublication[pillartypes.AssignableAdapters](
		device, "domainmgr", false, "global", &aa)
	if err != nil {
		return pillartypes.IoBundle{}, err
	}
	for _, ib := range aa.IoBundleList {
		if ib.Phylabel == phylabel {
			return ib, nil
		}
	}
	return pillartypes.IoBundle{}, fmt.Errorf(
		"no I/O bundle with physical label %q among %d bundles",
		phylabel, len(aa.IoBundleList))
}

// expectVfioOwnsPCIDevice asserts that the PCI device is bound to vfio-pci
// and pinned to it through driver_override, i.e. that the host has handed
// it over to a guest and no other driver can claim it back.
func expectVfioOwnsPCIDevice(g Gomega, device *evetest.EdgeDevice, pciLong string) {
	devDir := "/sys/bus/pci/devices/" + pciLong
	stdout, _, err := device.RunShellScript(
		fmt.Sprintf("readlink %s/driver; cat %s/driver_override", devDir, devDir),
		pciSysfsCmdTimeout, 0)
	g.Expect(err).ToNot(HaveOccurred())
	fields := strings.Fields(stdout)
	g.Expect(fields).To(HaveLen(2),
		"driver symlink and driver_override of %s: %q", pciLong, stdout)
	g.Expect(path.Base(fields[0])).To(Equal("vfio-pci"), "driver bound to %s", pciLong)
	g.Expect(fields[1]).To(Equal("vfio-pci"), "driver_override of %s", pciLong)
}

// setBoolConfigProperty sets one boolean device config property, replacing
// an earlier value of the same key. SetConfigProperties only appends, so
// toggling a property through it alone would leave two entries for one key.
func setBoolConfigProperty(devConfig *evetest.EdgeDeviceConfig,
	key pillartypes.GlobalSettingKey, value bool) {
	kept := make([]*eveconfig.ConfigItem, 0, len(devConfig.ConfigItems))
	for _, item := range devConfig.ConfigItems {
		if item.GetKey() != string(key) {
			kept = append(kept, item)
		}
	}
	devConfig.ConfigItems = kept
	cfgProps := pillartypes.NewConfigItemValueMap()
	cfgProps.SetGlobalValueBool(key, value)
	devConfig.SetConfigProperties(cfgProps)
}

// pciAccess is one access observed on the EVE host: the open of a PCI device
// attribute or of a console attach point, or a call of a kernel function that
// resets a PCI device, writes its config space or maps one of its BARs.
type pciAccess struct {
	Phase string // tracer phase the access falls into
	Comm  string // name of the accessing process
	PID   int
	// PComm and PPID name the accessing process's parent, GPComm and GPPID
	// its grandparent. The tracer learns ancestry at fork, so they are empty
	// and 0 for a process older than the tracer, and the grandparent also
	// when the parent is older than the tracer.
	PComm  string
	PPID   int
	GPComm string
	GPPID  int
	Path   string // opened file; empty for a kernel function call
	Flags  uint32 // open(2) flags of the open; meaningless otherwise
	Func   string // called kernel function; empty for an open
}

var (
	// pciBDFRE matches a PCI address (domain:bus:device.function) in a path.
	pciBDFRE = regexp.MustCompile(`[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]`)
	// procBusPCIDeviceRE matches the legacy procfs file of some PCI device,
	// /proc/bus/pci/<bus>/<device>.<function> with the domain prefixed to the
	// bus outside domain 0.
	procBusPCIDeviceRE = regexp.MustCompile(`^/proc/bus/pci/(?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}/[0-9a-fA-F]{2}\.[0-7]`)
)

// procBusPCIPath returns the legacy procfs file of the PCI device at the
// given address, e.g. /proc/bus/pci/00/01.0 for 0000:00:01.0, or "" for a
// malformed address.
func procBusPCIPath(bdf string) string {
	parts := strings.SplitN(bdf, ":", 3)
	if len(parts) != 3 {
		return ""
	}
	bus := parts[1]
	if parts[0] != "0000" {
		bus = parts[0] + ":" + parts[1]
	}
	return "/proc/bus/pci/" + bus + "/" + parts[2]
}

// concernsDevice reports whether the access may involve the PCI device at the
// given address: an open of a path naming that address (its sysfs directory,
// through whichever path it is reached, or its legacy procfs file); an open
// of a path naming no device at all, such as drivers_probe, rescan, a
// driver's bind and unbind files or /dev/mem, whose target is written into
// the file and therefore not visible in the path; a console attach point; or
// a kernel function, which does not reveal the device it acts on. Opens of
// paths naming another device's address do not concern the device.
func (a pciAccess) concernsDevice(bdf string) bool {
	if a.Func != "" || a.isConsole() {
		return true
	}
	if strings.Contains(a.Path, bdf) {
		return true
	}
	if procPath := procBusPCIPath(bdf); procPath != "" && strings.HasPrefix(a.Path, procPath) {
		return true
	}
	// A path naming some other device, in its sysfs or its procfs form,
	// does not concern this one; a path naming no device may.
	return !pciBDFRE.MatchString(a.Path) && !procBusPCIDeviceRE.MatchString(a.Path)
}

// pciAccessesConcerning returns the accesses that may involve the PCI device
// at the given address, see concernsDevice.
func pciAccessesConcerning(accesses []pciAccess, bdf string) []pciAccess {
	var concerning []pciAccess
	for _, access := range accesses {
		if access.concernsDevice(bdf) {
			concerning = append(concerning, access)
		}
	}
	return concerning
}

// hasAnyPrefix reports whether s starts with one of the prefixes.
func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// isWriteOpen reports whether the access opened a file for writing.
func (a pciAccess) isWriteOpen() bool {
	return a.Func == "" && a.Flags&openAccessModeMask != openReadOnly
}

// isConsole reports whether the access is the open of a console attach point
// rather than of a PCI device attribute.
func (a pciAccess) isConsole() bool {
	return a.Func == "" && hasAnyPrefix(a.Path, consolePathPrefixes)
}

// isViolation reports whether the access is one the host must not make while
// a device is passed through: any write-open of a PCI device attribute, and
// any reset, config-space write or BAR mapping by a process other than qemu,
// which drives the device on the guest's behalf. The traced kernel functions
// do not reveal which device they act on, so a reset of some other device by
// a host process counts as well. Console attach points are not covered: EVE
// is expected to bind and unbind its framebuffer console when
// debug.enable.vga is switched, so those opens are only reported.
func (a pciAccess) isViolation() bool {
	if a.Func != "" {
		return !strings.HasPrefix(a.Comm, "qemu-system-")
	}
	return a.isWriteOpen() && hasAnyPrefix(a.Path, pciPathPrefixes)
}

// describeAncestor renders a parent or grandparent as comm/pid, or as
// unknown when the tracer never saw it forked.
func describeAncestor(comm string, pid int) string {
	if pid == 0 && comm == "" {
		return "unknown (older than the tracer)"
	}
	return fmt.Sprintf("%s/%d", comm, pid)
}

func (a pciAccess) String() string {
	who := fmt.Sprintf("comm=%s pid=%d parent=%s grandparent=%s", a.Comm, a.PID,
		describeAncestor(a.PComm, a.PPID), describeAncestor(a.GPComm, a.GPPID))
	if a.Func != "" {
		return fmt.Sprintf("[%s] %s %s", a.Phase, a.Func, who)
	}
	what := "open"
	if a.isConsole() {
		what = "console open"
	}
	mode := "read"
	if a.isWriteOpen() {
		mode = "WRITE"
	}
	return fmt.Sprintf("[%s] %s for %s %s flags=0x%x path=%s",
		a.Phase, what, mode, who, a.Flags, a.Path)
}

// formatPCIAccesses renders the accesses one per line for a log or failure
// message.
func formatPCIAccesses(accesses []pciAccess) string {
	lines := make([]string, 0, len(accesses))
	for _, access := range accesses {
		lines = append(lines, "  "+access.String())
	}
	return strings.Join(lines, "\n")
}

// pciAccessViolations returns the recorded accesses the host must not have
// made, leaving out the tracer's own self-test.
func pciAccessViolations(accesses []pciAccess) []pciAccess {
	var violations []pciAccess
	for _, access := range accesses {
		if access.Phase != phaseSelfTest && access.isViolation() {
			violations = append(violations, access)
		}
	}
	return violations
}

// pciConsoleWrites returns the recorded write-opens of console attach points,
// i.e. the host's framebuffer console being bound or unbound.
func pciConsoleWrites(accesses []pciAccess) []pciAccess {
	var writes []pciAccess
	for _, access := range accesses {
		if access.isConsole() && access.isWriteOpen() {
			writes = append(writes, access)
		}
	}
	return writes
}

// expectSelfTestRecorded asserts that the tracer recorded the control write
// of its self-test, proving it caught writes before the test relies on it
// having seen none.
func expectSelfTestRecorded(t *WithT, accesses []pciAccess, controlAttr string) {
	for _, access := range accesses {
		if access.Phase == phaseSelfTest && access.Path == controlAttr && access.isWriteOpen() {
			return
		}
	}
	t.Expect(false).To(BeTrue(),
		"the tracer did not record its own control write to %s; recorded accesses:\n%s",
		controlAttr, formatPCIAccesses(accesses))
}

// pciAccessTracer records, on the EVE host, every process that opens a PCI
// device attribute (the sysfs tree under /sys/bus/pci and /sys/devices/pci*,
// the legacy /proc/bus/pci files and /dev/mem) or a console attach point (see
// consolePathPrefixes), and every call of the kernel functions through which
// a device is reset, its config space written or a BAR mapped. It is the
// bpftrace script testdata/pciaccess.bt, driven end to end by
// eve-tools/bpftrace-compiler's run-via-ssh command: the compiler learns the
// device's kernel over SSH, compiles the script for it (through its cache),
// uploads it and runs it with bpftrace-aotrt, then prints the script's JSON
// output once the run ends. The observation is split into named phases by
// markers (see mark), so an access can be attributed to what the test was
// doing at the time; the script exits on the end marker.
type pciAccessTracer struct {
	device *evetest.EdgeDevice
	log    *logrus.Logger
	binDir string             // holds the compiler binary
	cancel context.CancelFunc // kills the compiler
	cmd    *exec.Cmd
	stdout bytes.Buffer  // the script's output, printed by the compiler at the end
	ready  chan struct{} // closed once the compiler starts the script on the device
	done   chan struct{} // closed once the compiler exited
	waited error         // its exit status, valid once done is closed

	stderrMu   sync.Mutex
	stderrTail []string // last lines of the compiler's stderr, for messages
}

var (
	// bpftraceOpenLineRE and bpftraceKernelLineRE match the two printf
	// formats of the tracer script: who (comm and pid of the process, its
	// parent and its grandparent) followed by what.
	bpftraceOpenLineRE   = regexp.MustCompile(`^open comm=(.*) pid=(\d+) ppid=(\d+) pcomm=(.*) gppid=(\d+) gpcomm=(.*) flags=0x([0-9a-fA-F]+) path=(.*)$`)
	bpftraceKernelLineRE = regexp.MustCompile(`^kernel comm=(.*) pid=(\d+) ppid=(\d+) pcomm=(.*) gppid=(\d+) gpcomm=(.*) func=(\S+)$`)
)

// bpftraceMessage is one line of bpftrace's JSON output.
type bpftraceMessage struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

// tracerToolingMissing reports that the machine running the test lacks what
// running the tracer needs. The test skips on it rather than failing, as with
// any other unmet requirement.
type tracerToolingMissing struct {
	what string
}

func (e *tracerToolingMissing) Error() string {
	return e.what
}

// checkTracerTooling verifies that the device's architecture is the one the
// tracer script is written for and that the compiler sources and the tools
// the compiler and this file need are available on the test runner.
func checkTracerTooling(arch, compilerDir string) error {
	if arch != "amd64" {
		return &tracerToolingMissing{what: fmt.Sprintf(
			"the tracer script traces the amd64 syscalls, the device is %s", arch)}
	}
	if _, err := os.Stat(filepath.Join(compilerDir, "root", "build.yml")); err != nil {
		return &tracerToolingMissing{what: fmt.Sprintf(
			"the bpftrace-compiler sources are not at %s (%v); make evetest mounts them "+
				"from the EVE checkout, elsewhere point %s at them",
			compilerDir, err, bpftraceCompilerDirParamKey)}
	}
	for _, tool := range []string{"go", "docker", "qemu-system-x86_64", "ssh-keyscan", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			return &tracerToolingMissing{what: fmt.Sprintf(
				"%s is not installed on the test runner but running the tracer needs it; "+
					"rebuild the evetest image if the runner is the evetest container", tool)}
		}
	}
	if _, err := os.Stat(eveSSHKeyPath); err != nil {
		return &tracerToolingMissing{what: fmt.Sprintf(
			"the EVE SSH key is not at %s (%v), where the framework keeps it in the "+
				"evetest container", eveSSHKeyPath, err)}
	}
	return nil
}

// trustHostKey records the current SSH host key of addr in the test runner's
// known_hosts, replacing any earlier one for that address: the compiler
// verifies host keys against that file and, unattended, refuses an unknown
// or changed key. Devices are recreated with new keys all the time.
func trustHostKey(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	knownHosts := filepath.Join(sshDir, "known_hosts")
	// known_hosts names non-standard ports as [host]:port.
	name := host
	if port != "22" {
		name = "[" + host + "]:" + port
	}
	// Best effort: there may be no entry to remove, and no file yet.
	_ = exec.CommandContext(ctx, "ssh-keygen", "-f", knownHosts, "-R", name).Run()
	keys, err := exec.CommandContext(ctx, "ssh-keyscan", "-T", "10", "-p", port, host).Output()
	if err != nil {
		return fmt.Errorf("ssh-keyscan %s: %w", addr, err)
	}
	if len(bytes.TrimSpace(keys)) == 0 {
		return fmt.Errorf("ssh-keyscan %s returned no host key", addr)
	}
	f, err := os.OpenFile(knownHosts, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(keys); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// startPCIAccessTracer gets the tracer running on the device through the
// compiler's run-via-ssh command and returns once the compiler has started
// the script there. The test is skipped when the test runner lacks the
// compiler sources (compilerDir) or the tools needed, and fails when
// compiling fails or the tracer does not come up.
func startPCIAccessTracer(evetestT *evetest.T, device *evetest.EdgeDevice,
	compilerDir string) *pciAccessTracer {
	log := evetest.Logger()
	scriptPath, err := filepath.Abs(filepath.Join("testdata", "pciaccess.bt"))
	if err != nil {
		evetestT.Fatalf("Failed to locate the tracer script: %v", err)
	}
	if _, err := os.Stat(scriptPath); err != nil {
		evetestT.Fatalf("Tracer script: %v", err)
	}
	err = checkTracerTooling(device.GetArch(), compilerDir)
	var missing *tracerToolingMissing
	if errors.As(err, &missing) {
		evetestT.Skipf("Cannot run the PCI access tracer: %s", missing.what)
	}
	if err != nil {
		evetestT.Fatalf("Cannot run the PCI access tracer: %v", err)
	}

	tr := &pciAccessTracer{
		device: device,
		log:    log,
		ready:  make(chan struct{}),
		done:   make(chan struct{}),
	}
	started := false
	// A Fatalf below runs the deferred calls; until the tracer is handed to
	// the caller, whose deferred stop() takes over, clean up here.
	defer func() {
		if !started {
			tr.stop()
		}
	}()

	sshAddr, err := device.ReachableAddress(22)
	if err != nil {
		evetestT.Fatalf("Failed to find the SSH endpoint of %s: %v", device.Name(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	tr.cancel = cancel
	if err := trustHostKey(ctx, sshAddr); err != nil {
		evetestT.Fatalf("Failed to record the SSH host key of %s: %v", device.Name(), err)
	}

	tr.binDir, err = os.MkdirTemp("", "bpftrace-compiler-")
	if err != nil {
		evetestT.Fatalf("Failed to create a directory for the compiler: %v", err)
	}
	compiler := filepath.Join(tr.binDir, "bpftrace-compiler")
	// The compiler vendors its dependencies and is not part of any Go
	// workspace the test runner may have set up.
	buildEnv := append(os.Environ(), "GOFLAGS=-mod=vendor", "GOWORK=off")
	log.Infof("Building bpftrace-compiler from %s...", compilerDir)
	buildCtx, cancelBuild := context.WithTimeout(ctx, pciTracerStartTimeout)
	defer cancelBuild()
	if err := runLogged(buildCtx, log, compilerDir, buildEnv, "go", "build", "-o", compiler, "."); err != nil {
		evetestT.Fatalf("Failed to build bpftrace-compiler: %v", err)
	}

	// The compiler resolves its root/ package relative to the working
	// directory, so it runs from its own sources. Its own progress goes to
	// stderr and is relayed to the log; the script's output arrives on
	// stdout once the run ends.
	log.Infof("Running the PCI access tracer %s on %s through bpftrace-compiler "+
		"(unless cached, compiling boots a VM with the device's kernel and may take "+
		"several minutes)...", filepath.Base(scriptPath), device.Name())
	tr.cmd = exec.CommandContext(ctx, compiler, "run-via-ssh",
		"-i", eveSSHKeyPath, "-t", pciTracerRunTimeout.String(), sshAddr, scriptPath)
	tr.cmd.Dir = compilerDir
	tr.cmd.Stdout = &tr.stdout
	stderr, err := tr.cmd.StderrPipe()
	if err != nil {
		evetestT.Fatalf("Failed to set up the compiler's stderr: %v", err)
	}
	if err := tr.cmd.Start(); err != nil {
		evetestT.Fatalf("Failed to start bpftrace-compiler: %v", err)
	}
	go tr.relayStderr(stderr)
	go func() {
		tr.waited = tr.cmd.Wait()
		close(tr.done)
	}()

	select {
	case <-tr.ready:
	case <-tr.done:
		evetestT.Fatalf("bpftrace-compiler exited before running the tracer (%v); "+
			"its last output:\n%s\nthe script's output:\n%s",
			tr.waited, tr.lastStderr(), tr.stdout.String())
	case <-time.After(pciTracerStartTimeout):
		evetestT.Fatalf("bpftrace-compiler did not get the tracer running within %v; "+
			"its last output:\n%s", pciTracerStartTimeout, tr.lastStderr())
	}
	// The compiler reports before the runtime has attached its probes.
	time.Sleep(pciTracerAttachDelay)
	started = true
	log.Infof("PCI access tracer running on %s", device.Name())
	return tr
}

// relayStderr forwards the compiler's stderr to the log line by line, keeps
// the last lines for messages, and signals readiness when the compiler
// reports having started the script on the device.
func (tr *pciAccessTracer) relayStderr(stderr io.Reader) {
	const keepLines = 40
	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	ready := false
	for scanner.Scan() {
		line := scanner.Text()
		tr.log.Infof("bpftrace-compiler: %s", line)
		tr.stderrMu.Lock()
		tr.stderrTail = append(tr.stderrTail, line)
		if len(tr.stderrTail) > keepLines {
			tr.stderrTail = tr.stderrTail[len(tr.stderrTail)-keepLines:]
		}
		tr.stderrMu.Unlock()
		if !ready && strings.Contains(line, compilerRunningMarker) {
			ready = true
			close(tr.ready)
		}
	}
}

// lastStderr returns the last lines of the compiler's stderr.
func (tr *pciAccessTracer) lastStderr() string {
	tr.stderrMu.Lock()
	defer tr.stderrMu.Unlock()
	return strings.Join(tr.stderrTail, "\n")
}

// runLogged runs a command in dir with the given environment, streaming its
// output into log.
func runLogged(ctx context.Context, log *logrus.Logger, dir string, env []string,
	name string, args ...string) error {
	output := log.Writer()
	defer func() { _ = output.Close() }()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), ctx.Err())
		}
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

// mark starts a new phase: accesses recorded from now on are attributed to
// it. The marker is the open of a non-existent path the tracer records like
// any other; the pause afterwards keeps it ordered before the phase's own
// accesses in the merged per-CPU output.
func (tr *pciAccessTracer) mark(phase string) {
	script := fmt.Sprintf("cat %s%s 2>/dev/null || true\nsleep 1\n", pciTracerPhaseDir, phase)
	_, stderr, err := tr.device.RunShellScript(script, pciSysfsCmdTimeout, 0)
	if err != nil {
		tr.log.Warnf("Failed to mark tracer phase %q: %v (stderr: %s)", phase, err, stderr)
	}
	tr.log.Infof("PCI access tracer phase: %s", phase)
}

// selfTestWrite performs the tracer's self-test: it writes the current value
// of the control device's power/control attribute back, a no-op for the
// device, in a phase of its own. finish's output must show the write, see
// expectSelfTestRecorded. It returns the attribute written.
func (tr *pciAccessTracer) selfTestWrite(t *WithT, controlPCI string) string {
	tr.mark(phaseSelfTest)
	attr := "/sys/bus/pci/devices/" + controlPCI + "/power/control"
	script := fmt.Sprintf("set -e\nv=$(cat %s)\necho \"$v\" > %s\n", attr, attr)
	_, stderr, err := tr.device.RunShellScript(script, pciSysfsCmdTimeout, 0)
	t.Expect(err).ToNot(HaveOccurred(), "control write to %s (stderr: %s)", attr, stderr)
	return attr
}

// finish sets the end marker, on which the tracer script exits, waits for the
// compiler to hand over the script's output and returns every recorded
// access, in order and attributed to its phase.
func (tr *pciAccessTracer) finish() ([]pciAccess, error) {
	tr.mark(phaseEnd)
	select {
	case <-tr.done:
	case <-time.After(pciTracerFinishTimeout):
		tr.cancel()
		<-tr.done
		return nil, fmt.Errorf("the tracer did not exit within %v of the end marker; "+
			"the compiler's last output:\n%s", pciTracerFinishTimeout, tr.lastStderr())
	}
	if tr.waited != nil {
		return nil, fmt.Errorf("bpftrace-compiler failed: %w; its last output:\n%s",
			tr.waited, tr.lastStderr())
	}
	return parseCompilerOutput(tr.stdout.String())
}

// parseCompilerOutput extracts the accesses from what run-via-ssh prints on
// its stdout: whatever the image build wrote there (docker's "Loaded image:"
// lines, for example), then the script's JSON output, then the remote stderr
// behind a separator when there was any. Only the JSON objects are the
// script's. The run must have reached the point of attaching its probes.
func parseCompilerOutput(output string) ([]pciAccess, error) {
	var jsonLines []string
	attached := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == compilerStderrSeparator {
			break
		}
		if !strings.HasPrefix(line, "{") {
			continue
		}
		if strings.Contains(line, `"attached_probes"`) {
			attached = true
		}
		jsonLines = append(jsonLines, line)
	}
	if !attached {
		return nil, fmt.Errorf("the tracer never reported its probes attached; "+
			"the compiler printed:\n%s", output)
	}
	return parsePCIAccessTrace(strings.Join(jsonLines, "\n"))
}

// parsePCIAccessTrace turns the tracer's JSON output into accesses. Lost
// events and lines that cannot be parsed are errors, as the trace would not
// be trustworthy; messages other than printf are ignored.
func parsePCIAccessTrace(output string) ([]pciAccess, error) {
	var accesses []pciAccess
	phase := "before-first-phase"
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var msg bpftraceMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			return nil, fmt.Errorf("unparsable tracer output line %q: %w", line, err)
		}
		switch msg.Type {
		case "lost_events":
			return nil, fmt.Errorf("the tracer lost events: %s", msg.Data)
		case "printf":
		default:
			continue
		}
		var text string
		if err := json.Unmarshal(msg.Data, &text); err != nil {
			return nil, fmt.Errorf("unparsable printf data in tracer output line %q: %w",
				line, err)
		}
		text = strings.TrimRight(text, "\n")
		if fields := bpftraceOpenLineRE.FindStringSubmatch(text); fields != nil {
			access, err := pciAccessBy(phase, fields[1:7])
			if err != nil {
				return nil, fmt.Errorf("unparsable tracer output %q: %w", text, err)
			}
			flags, err := strconv.ParseUint(fields[7], 16, 32)
			if err != nil {
				return nil, fmt.Errorf("unparsable flags in tracer output %q: %w", text, err)
			}
			if marker, ok := strings.CutPrefix(fields[8], pciTracerPhaseDir); ok {
				phase = marker
				continue
			}
			access.Path = fields[8]
			access.Flags = uint32(flags)
			accesses = append(accesses, access)
			continue
		}
		if fields := bpftraceKernelLineRE.FindStringSubmatch(text); fields != nil {
			access, err := pciAccessBy(phase, fields[1:7])
			if err != nil {
				return nil, fmt.Errorf("unparsable tracer output %q: %w", text, err)
			}
			access.Func = fields[7]
			accesses = append(accesses, access)
			continue
		}
		return nil, fmt.Errorf("unexpected tracer output %q", text)
	}
	return accesses, nil
}

// pciAccessBy returns an access by the process named in a tracer record,
// given the record's who-fields in order (comm, pid, ppid, pcomm, gppid,
// gpcomm), with what was accessed left for the caller to fill in.
func pciAccessBy(phase string, who []string) (pciAccess, error) {
	if len(who) != 6 {
		return pciAccess{}, fmt.Errorf("%d process fields, want 6", len(who))
	}
	var pids [3]int
	for i, field := range []string{who[1], who[2], who[4]} {
		pid, err := strconv.Atoi(field)
		if err != nil {
			return pciAccess{}, fmt.Errorf("pid field %q: %w", field, err)
		}
		pids[i] = pid
	}
	return pciAccess{
		Phase:  phase,
		Comm:   who[0],
		PID:    pids[0],
		PPID:   pids[1],
		PComm:  who[3],
		GPPID:  pids[2],
		GPComm: who[5],
	}, nil
}

// stop ends the tracer if it still runs, which closes the SSH session and
// with it the script on the device, and removes what the run left behind:
// the compiler binary here and the uploaded script on the device.
func (tr *pciAccessTracer) stop() {
	if tr.cancel != nil {
		tr.cancel()
	}
	if tr.cmd != nil && tr.cmd.Process != nil {
		<-tr.done
	}
	if tr.binDir != "" {
		if err := os.RemoveAll(tr.binDir); err != nil {
			tr.log.Warnf("Failed to remove %s: %v", tr.binDir, err)
		}
	}
	_, stderr, err := tr.device.RunShellScript("rm -f "+compilerRemoteAOTPath,
		pciSysfsCmdTimeout, 0)
	if err != nil {
		tr.log.Warnf("Failed to remove %s from the device: %v (stderr: %s)",
			compilerRemoteAOTPath, err, stderr)
	}
}
