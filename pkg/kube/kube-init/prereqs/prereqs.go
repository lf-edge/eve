// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package prereqs satisfies the system-level prerequisites kube-init
// needs before k3s can start: kernel modules, /var/lib mount,
// vault unsealing, network reachability, EdgeNodeInfo arrival,
// containerd start, CNI plugin staging, and friends. All operations
// are idempotent and ctx-cancellable.
package prereqs

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/lf-edge/eve/pkg/kube/kube-init/k3s"
	"github.com/lf-edge/eve/pkg/kube/kube-init/state"
)

// Filesystem paths. Most are prereqs-internal; the ones used by
// other packages (monitor's running-state housekeeping) are
// exported.
const (
	// KubeLogDir is the persist-backed directory under which
	// kube-init and k3s drop their log files. Exported because
	// monitor's log rotation + crash-log capture read from it.
	KubeLogDir = "/persist/kubelog"

	// CNIBinDir / OptCNIDir / CNISrcDir are the CNI plugin
	// directories. Exported because monitor's running-state tick
	// recopies plugins when they go missing on a kube container
	// restart.
	CNIBinDir = "/var/lib/cni/bin"
	OptCNIDir = "/opt/cni/bin"
	CNISrcDir = "/usr/libexec/cni"
)

const (
	containerdUserLog    = KubeLogDir + "/containerd-user.log"
	initialK3sVersion    = KubeLogDir + "/initial_k3s_version"
	kubeRootExt4         = "/persist/vault/kube"
	kubeRootZFS          = "/dev/zvol/persist/etcd-storage"
	kubeRootMountpoint   = "/var/lib"
	persistTypeFile      = "/run/eve.persist_type"
	eveReleasePath       = "/run/eve-release"
	osReleasePath        = "/etc/os-release"
	containerdBinDir     = "/var/lib/rancher/k3s/data/current/bin"
	containerdConfigPath = "/etc/containerd/config-k3s.toml"
	containerdSockDir    = "/run/containerd-user"
	runcSymlink          = "/usr/bin/runc"
	shimSymlink          = "/usr/bin/containerd-shim-runc-v2"
	eveBridgeSrc         = "/usr/bin/eve-bridge"

	// cpuManagerStateFile is kubelet's persistent record of the
	// active CPU-manager policy. If it disagrees with the
	// kubelet-arg cpu-manager-policy in config.yaml on next
	// start, k3s refuses to boot. See CleanCPUManagerState.
	cpuManagerStateFile = "/var/lib/kubelet/cpu_manager_state"
)

// Polling cadences. Test code may shrink these via t.Cleanup.
var (
	defaultPollInterval = 5 * time.Second
	filePollInterval    = 1 * time.Second
	containerdTimeout   = 30 * time.Second
	procNetRoute        = "/proc/net/route"
	procMounts          = "/proc/mounts"
	procRoot            = "/proc"
	hostnameBin         = "/bin/hostname"
)

// kernelModules lists modules to modprobe at startup. Individual
// failures are logged but not fatal — some modules may not exist on
// every platform variant.
var kernelModules = []string{"tun", "vhost_net", "fuse", "iscsi_tcp"}

// uuidRegexp validates an RFC-4122 UUID string (lowercase or upper).
var uuidRegexp = regexp.MustCompile(
	`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// edgeNodeInfo is the subset of EdgeNodeInfo JSON we consume.
type edgeNodeInfo struct {
	DeviceName string `json:"DeviceName"`
}

// RunAll orchestrates every prerequisite in the order the FSM needs:
// logging+filesystem layout → kernel modules → cgroups → network →
// device identity → vault → mounts → release info.
//
// Returns the device name, UUID, and EVE release on success.
// CheckNetwork is best-effort (logs only); the rest fail-fast.
func RunAll(ctx context.Context) (deviceName, uuid, eveRelease string, err error) {
	log.Printf("starting system prerequisites")

	for _, step := range []struct {
		name string
		fn   func() error
	}{
		{"SetupLogging", SetupLogging},
		{"LoadKernelModules", LoadKernelModules},
		{"SetupCgroup", SetupCgroup},
		{"MakeMountShared", MakeMountShared},
		{"StartISCSI", StartISCSI},
		{"FixDevNull", FixDevNull},
	} {
		if err := step.fn(); err != nil {
			return "", "", "", fmt.Errorf("%s: %w", step.name, err)
		}
	}

	if err := WaitNetwork(ctx); err != nil {
		return "", "", "", fmt.Errorf("WaitNetwork: %w", err)
	}

	deviceName, uuid, err = WaitDeviceName(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("WaitDeviceName: %w", err)
	}

	if err := WaitVault(ctx); err != nil {
		return "", "", "", fmt.Errorf("WaitVault: %w", err)
	}

	// Migrate any pre-vault kube-save-var-lib backup now that the
	// vault is available. No-op on devices that never had the
	// legacy location.
	if err := state.MigrateVarLib(); err != nil {
		return "", "", "", fmt.Errorf("MigrateVarLib: %w", err)
	}

	if err := MountKubeRoot(); err != nil {
		return "", "", "", fmt.Errorf("MountKubeRoot: %w", err)
	}

	CheckNetwork()

	if err := CleanCPUManagerState(); err != nil {
		// Non-fatal: a corrupted state file is logged but does
		// not block boot. k3s will fail to start later with a
		// clearer error message that the operator can act on.
		log.Printf("WARNING: CleanCPUManagerState: %v", err)
	}

	eveRelease, err = WaitEveRelease(ctx)
	if err != nil {
		return "", "", "", fmt.Errorf("WaitEveRelease: %w", err)
	}

	log.Printf("all prerequisites satisfied: device=%s uuid=%s release=%s",
		deviceName, uuid, eveRelease)
	return deviceName, uuid, eveRelease, nil
}

// ---------------------------------------------------------------------------
// Polling helpers
// ---------------------------------------------------------------------------

// waitForFile polls until path exists or ctx is cancelled.
func waitForFile(ctx context.Context, path string, interval time.Duration) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	log.Printf("waiting for %s to appear", path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for %s: %w", path, ctx.Err())
		case <-ticker.C:
			if _, err := os.Stat(path); err == nil {
				log.Printf("%s appeared", path)
				return nil
			}
		}
	}
}

// waitForBlockDevice polls until path is a block device or ctx
// expires. Used for ZFS zvol arrival on `persist`.
func waitForBlockDevice(ctx context.Context, path string, interval time.Duration) error {
	log.Printf("waiting for block device %s", path)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if info, err := os.Stat(path); err == nil && info.Mode()&os.ModeDevice != 0 {
			log.Printf("block device %s available", path)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for block device %s: %w", path, ctx.Err())
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// /proc parsers (pure functions; testable with canned input)
// ---------------------------------------------------------------------------

// isProcessRunning scans procRoot for a process whose argv contains
// cmdSubstr. Returns false on any I/O error (best-effort check).
func isProcessRunning(cmdSubstr string) bool {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join(procRoot, name, "cmdline"))
		if err != nil {
			continue
		}
		// /proc/<pid>/cmdline uses NUL as the argv separator.
		if strings.Contains(strings.ReplaceAll(string(cmdline), "\x00", " "),
			cmdSubstr) {
			return true
		}
	}
	return false
}

// hasDefaultRoute reports whether procNetRoute lists a default route
// (destination 00000000, mask 00000000). Returns false on I/O error.
func hasDefaultRoute() bool {
	f, err := os.Open(procNetRoute)
	if err != nil {
		return false
	}
	defer f.Close()
	return scanForDefaultRoute(f)
}

// scanForDefaultRoute is the pure half of hasDefaultRoute, factored
// out so tests can drive it with canned /proc/net/route content.
func scanForDefaultRoute(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
	first := true
	for scanner.Scan() {
		if first {
			first = false // header line
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		if fields[1] == "00000000" && fields[7] == "00000000" {
			return true
		}
	}
	return false
}

// isMounted reports whether mountpoint appears in procMounts.
func isMounted(mountpoint string) bool {
	f, err := os.Open(procMounts)
	if err != nil {
		return false
	}
	defer f.Close()
	return scanForMountpoint(f, mountpoint)
}

func scanForMountpoint(r io.Reader, mountpoint string) bool {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 2 && fields[1] == mountpoint {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Command + filesystem helpers
// ---------------------------------------------------------------------------

func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		log.Printf("command failed: %s %s: %v: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return nil
}

func runCmdOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w",
			name, strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out)), nil
}

func mkdirAll(path string, perm os.FileMode) error {
	if err := os.MkdirAll(path, perm); err != nil {
		return fmt.Errorf("mkdir %s: %w", path, err)
	}
	return nil
}

// symlinkIfNeeded creates dst → src when src exists and dst is not
// already pointing there. Missing src silently no-ops.
func symlinkIfNeeded(src, dst string) error {
	if _, err := os.Stat(src); err != nil {
		log.Printf("symlink source %s does not exist, skipping", src)
		return nil
	}
	if target, err := os.Readlink(dst); err == nil && target == src {
		return nil
	}
	// Best-effort cleanup before recreating.
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		log.Printf("warning: remove existing %s: %v", dst, err)
	}
	if err := os.Symlink(src, dst); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", dst, src, err)
	}
	log.Printf("created symlink %s -> %s", dst, src)
	return nil
}

func copyFile(src, dst string) (retErr error) {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("create %s: %w", dst, err)
	}
	defer func() {
		if cerr := out.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}
	return nil
}

func copyDirContents(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read dir %s: %w", srcDir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := copyFile(filepath.Join(srcDir, entry.Name()),
			filepath.Join(dstDir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

// WaitNetwork blocks until /proc/net/route shows a default route.
func WaitNetwork(ctx context.Context) error {
	log.Printf("waiting for default route")
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	for {
		if hasDefaultRoute() {
			log.Printf("default route found")
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for default route: %w", ctx.Err())
		case <-ticker.C:
			log.Printf("still waiting for default route...")
		}
	}
}

// CheckNetwork is a best-effort external connectivity probe. Failure
// is logged, never returned — kube-init must still proceed when the
// controller-side connectivity is constrained.
func CheckNetwork() {
	log.Printf("checking external network connectivity")
	out, err := exec.Command("curl", "-o", "/dev/null", "-w", "%{http_code}",
		"-s", "--max-time", "10", "https://get.k3s.io").Output()
	if err != nil {
		log.Printf("network connectivity check failed: %v (non-fatal)", err)
		return
	}
	code := strings.TrimSpace(string(out))
	if code == "200" {
		log.Printf("external network connectivity confirmed")
	} else {
		log.Printf("network connectivity check returned HTTP %s (non-fatal)", code)
	}
}

// ---------------------------------------------------------------------------
// Vault + persist mount
// ---------------------------------------------------------------------------

// WaitVault loops on `vaultmgr waitUnsealed` until it returns 0 or
// ctx expires. vaultmgr is built against pillar's libraries, so we
// inject LD_LIBRARY_PATH pointing at pillar's rootfs.
func WaitVault(ctx context.Context) error {
	log.Printf("waiting for vault to be unsealed")
	const pillarRootfs = "/hostfs/containers/services/pillar/rootfs"
	vaultmgrBin := pillarRootfs + "/opt/zededa/bin/vaultmgr"
	ldLibPath := pillarRootfs + "/usr/lib"

	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	attempt := 0
	for {
		attempt++
		cmd := exec.CommandContext(ctx, vaultmgrBin, "waitUnsealed")
		cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+ldLibPath)
		out, err := cmd.CombinedOutput()
		if err == nil {
			log.Printf("vault unsealed (attempt %d)", attempt)
			return nil
		}
		log.Printf("vault not ready (attempt %d): %v: %s",
			attempt, err, strings.TrimSpace(string(out)))
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for vault: %w", ctx.Err())
		case <-ticker.C:
		}
	}
}

// MountKubeRoot binds or mounts the persistent storage at
// kubeRootMountpoint based on /run/eve.persist_type. No-op when
// already mounted (idempotent).
func MountKubeRoot() error {
	if isMounted(kubeRootMountpoint) {
		log.Printf("%s already mounted, skipping", kubeRootMountpoint)
		return nil
	}
	data, err := os.ReadFile(persistTypeFile)
	if err != nil {
		return fmt.Errorf("read persist type from %s: %w", persistTypeFile, err)
	}
	persistType := strings.TrimSpace(string(data))

	switch persistType {
	case "zfs":
		log.Printf("using ZFS persistent storage; waiting for %s zvol", kubeRootZFS)
		// 10-minute ceiling for the zvol to appear; the FSM upstream
		// has no other watchdog over this step.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if err := waitForBlockDevice(ctx, kubeRootZFS, filePollInterval); err != nil {
			return fmt.Errorf("wait for zvol %s: %w", kubeRootZFS, err)
		}
		if err := syscall.Mount(kubeRootZFS, kubeRootMountpoint, "ext4", 0, ""); err != nil {
			return fmt.Errorf("mount %s to %s: %w",
				kubeRootZFS, kubeRootMountpoint, err)
		}
		log.Printf("mounted %s to %s", kubeRootZFS, kubeRootMountpoint)

	case "ext4":
		log.Printf("using ext4 persistent storage")
		if err := mkdirAll(kubeRootExt4, 0755); err != nil {
			return err
		}
		if err := syscall.Mount(kubeRootExt4, kubeRootMountpoint, "",
			syscall.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind mount %s to %s: %w",
				kubeRootExt4, kubeRootMountpoint, err)
		}
		log.Printf("bind-mounted %s to %s", kubeRootExt4, kubeRootMountpoint)

	default:
		return fmt.Errorf("unsupported persist type: %q", persistType)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Device identity + EVE release
// ---------------------------------------------------------------------------

// WaitDeviceName blocks until EdgeNodeInfo arrives, returning the
// operator-chosen DeviceName and the device UUID (from /bin/hostname,
// validated against the RFC-4122 shape).
//
// The Kubernetes node-name drop-in is rendered later by k3s.Configure
// — this function only resolves identity.
func WaitDeviceName(ctx context.Context) (deviceName, uuid string, err error) {
	log.Printf("waiting for device name from controller")
	if err := waitForFile(ctx, k3s.EdgeNodeInfoPath, defaultPollInterval); err != nil {
		return "", "", err
	}
	data, err := os.ReadFile(k3s.EdgeNodeInfoPath)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", k3s.EdgeNodeInfoPath, err)
	}
	var info edgeNodeInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return "", "", fmt.Errorf("parse %s: %w", k3s.EdgeNodeInfoPath, err)
	}
	if info.DeviceName == "" {
		return "", "", fmt.Errorf("DeviceName is empty in %s", k3s.EdgeNodeInfoPath)
	}
	log.Printf("device name: %s", info.DeviceName)

	uuid, err = waitForValidUUID(ctx)
	if err != nil {
		return "", "", err
	}
	log.Printf("device UUID: %s", uuid)
	return info.DeviceName, uuid, nil
}

// waitForValidUUID polls /bin/hostname until its output matches an
// RFC-4122 UUID. Pillar sets the kernel hostname to the device UUID
// during onboarding, so an unparsable value means onboarding is
// still in progress.
func waitForValidUUID(ctx context.Context) (string, error) {
	ticker := time.NewTicker(defaultPollInterval)
	defer ticker.Stop()
	for {
		out, err := runCmdOutput(hostnameBin)
		if err == nil && uuidRegexp.MatchString(out) {
			return out, nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for valid UUID: %w", ctx.Err())
		case <-ticker.C:
			log.Printf("waiting for valid UUID from %s (got %q)",
				hostnameBin, out)
		}
	}
}

// WaitEveRelease waits for /run/eve-release, mirrors it into
// /etc/os-release as PRETTY_NAME, and returns the release string.
func WaitEveRelease(ctx context.Context) (string, error) {
	log.Printf("waiting for EVE release info")
	if err := waitForFile(ctx, eveReleasePath, filePollInterval); err != nil {
		return "", err
	}
	data, err := os.ReadFile(eveReleasePath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", eveReleasePath, err)
	}
	release := strings.TrimSpace(string(data))
	if release == "" {
		return "", fmt.Errorf("empty EVE release in %s", eveReleasePath)
	}
	log.Printf("EVE release: %s", release)
	osContent := fmt.Sprintf("PRETTY_NAME=\"%s\"\n", release)
	if err := os.WriteFile(osReleasePath, []byte(osContent), 0644); err != nil {
		return "", fmt.Errorf("write %s: %w", osReleasePath, err)
	}
	log.Printf("wrote %s with PRETTY_NAME=%s", osReleasePath, release)
	return release, nil
}

// ---------------------------------------------------------------------------
// Kernel modules + cgroup + iSCSI + /dev/null
// ---------------------------------------------------------------------------

// LoadKernelModules modprobe's every entry in kernelModules.
// Individual failures are logged but do not abort: some modules
// (e.g. iscsi_tcp on minimal kernels) may legitimately be absent.
func LoadKernelModules() error {
	log.Printf("loading kernel modules: %v", kernelModules)
	for _, mod := range kernelModules {
		if err := runCmd("modprobe", mod); err != nil {
			log.Printf("warning: failed to load module %s: %v "+
				"(may not be available on this platform)", mod, err)
		} else {
			log.Printf("loaded kernel module: %s", mod)
		}
	}
	if err := mkdirAll("/run/lock", 0755); err != nil {
		log.Printf("warning: failed to create /run/lock: %v", err)
	}
	return nil
}

// SetupCgroup ensures /etc/fstab carries the cgroup mount entry.
// Idempotent: skipped when an entry containing
// "cgroup /sys/fs/cgroup cgroup" is already present.
func SetupCgroup() error {
	const fstabPath = "/etc/fstab"
	const cgroupEntry = "cgroup /sys/fs/cgroup cgroup defaults 0 0"
	data, err := os.ReadFile(fstabPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", fstabPath, err)
	}
	if strings.Contains(string(data), "cgroup /sys/fs/cgroup cgroup") {
		log.Printf("cgroup fstab entry already present")
		return nil
	}
	f, err := os.OpenFile(fstabPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open %s for append: %w", fstabPath, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintln(f, cgroupEntry); err != nil {
		return fmt.Errorf("write cgroup entry: %w", err)
	}
	log.Printf("added cgroup mount entry to %s", fstabPath)
	return nil
}

// MakeMountShared runs `mount --make-rshared /` so k3s can propagate
// mounts under it.
func MakeMountShared() error {
	log.Printf("making / mount shared (rshared)")
	if err := runCmd("mount", "--make-rshared", "/"); err != nil {
		return fmt.Errorf("make-rshared /: %w", err)
	}
	log.Printf("/ is now rshared")
	return nil
}

// StartISCSI starts /usr/sbin/iscsid as a detached background
// process if it isn't already running.
func StartISCSI() error {
	if isProcessRunning("iscsid") {
		log.Printf("iscsid already running")
		return nil
	}
	log.Printf("starting iscsid")
	cmd := exec.Command("/usr/sbin/iscsid")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start iscsid: %w", err)
	}
	log.Printf("iscsid started (PID %d)", cmd.Process.Pid)
	// iscsid daemonises itself; reap the immediate child to avoid a zombie.
	go func() { _ = cmd.Wait() }()
	return nil
}

// FixDevNull chmods /dev/null to 0666. Some container runtimes
// inherit a stricter mode from the host bind, which then breaks
// pods that write to it.
func FixDevNull() error {
	if err := os.Chmod("/dev/null", 0666); err != nil {
		return fmt.Errorf("chmod /dev/null: %w", err)
	}
	log.Printf("set /dev/null permissions to 0666")
	return nil
}

// CleanCPUManagerState removes /var/lib/kubelet/cpu_manager_state
// when its recorded policyName is "none". The CPU-manager policy
// is set via kubelet-arg in pkg/kube/config.yaml; if a previous
// boot ran with a different policy, the on-disk state file holds
// the OLD policy and kubelet refuses to start with the message
// "static policy: configured but state file contains invalid
// state".
//
// Why "none"? It is the historical default — devices that have
// been upgraded from an older EVE release have this on disk. The
// shell version of this check unconditionally deleted the file
// on policyName=none and left other values alone so a node
// already running the right policy (e.g. "static") keeps its
// state.
//
// A missing file is a no-op (fresh kubelet will write a new
// one). A corrupted file (unparsable JSON) is logged and left
// alone — kubelet will surface that more clearly than we can.
//
// Addresses upstream commit 1927e2f28 ("Delete cpu_manager_state
// file on every reboot"), with the policyName=="none" gate from
// commit 6719f918c.
func CleanCPUManagerState() error {
	data, err := os.ReadFile(cpuManagerStateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read %s: %w", cpuManagerStateFile, err)
	}
	var state struct {
		PolicyName string `json:"policyName"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		log.Printf("WARNING: parse %s: %v (leaving in place)",
			cpuManagerStateFile, err)
		return nil
	}
	if state.PolicyName != "none" {
		log.Printf("cpu_manager_state policyName=%q, no action",
			state.PolicyName)
		return nil
	}
	log.Printf("removing stale cpu_manager_state (policyName=none) from %s",
		cpuManagerStateFile)
	if err := os.Remove(cpuManagerStateFile); err != nil {
		return fmt.Errorf("remove %s: %w", cpuManagerStateFile, err)
	}
	return nil
}

// SetupLogging creates the kube log directory, symlinks /var/log
// at it (so any logger that defaults to /var/log lands on persist),
// pre-creates the k3s config drop-in directory, and records the
// initial k3s version once.
func SetupLogging() error {
	if err := mkdirAll(KubeLogDir, 0755); err != nil {
		return err
	}
	if target, err := os.Readlink("/var/log"); err != nil || target != KubeLogDir {
		// Best-effort: RemoveAll then symlink. A failure to remove
		// (e.g. /var/log is a non-empty dir we lack perms to wipe)
		// is logged via the symlink call below.
		_ = os.RemoveAll("/var/log")
		if err := os.Symlink(KubeLogDir, "/var/log"); err != nil {
			return fmt.Errorf("symlink /var/log -> %s: %w", KubeLogDir, err)
		}
		log.Printf("symlinked /var/log -> %s", KubeLogDir)
	}
	if err := mkdirAll(k3s.K3sConfigDir, 0755); err != nil {
		return err
	}
	if _, err := os.Stat(initialK3sVersion); os.IsNotExist(err) {
		if version, verr := runCmdOutput("k3s", "--version"); verr != nil {
			log.Printf("warning: could not determine k3s version: %v", verr)
		} else if err := os.WriteFile(initialK3sVersion,
			[]byte(version+"\n"), 0644); err != nil {
			log.Printf("warning: could not write initial k3s version: %v", err)
		} else {
			log.Printf("recorded initial k3s version: %s", version)
			syscall.Sync()
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// User containerd
// ---------------------------------------------------------------------------

// StartContainerd brings up the user-side containerd that k3s'
// kubelet talks to. Sets up runc/shim symlinks, starts containerd
// as a detached process if not already running, and waits for the
// socket to appear.
func StartContainerd(ctx context.Context) error {
	log.Printf("setting up containerd")
	if err := symlinkIfNeeded(filepath.Join(containerdBinDir, "runc"),
		runcSymlink); err != nil {
		return err
	}
	if err := symlinkIfNeeded(filepath.Join(containerdBinDir, "containerd-shim-runc-v2"),
		shimSymlink); err != nil {
		return err
	}
	if isProcessRunning("containerd -c "+containerdConfigPath) ||
		isProcessRunning("containerd --config "+containerdConfigPath) {
		log.Printf("user containerd already running")
		return waitForContainerdSock(ctx)
	}
	if err := mkdirAll(containerdSockDir, 0755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(containerdUserLog,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open containerd log %s: %w", containerdUserLog, err)
	}
	cmd := exec.Command(filepath.Join(containerdBinDir, "containerd"),
		"-c", containerdConfigPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start containerd: %w", err)
	}
	log.Printf("started user containerd (PID %d)", cmd.Process.Pid)
	// Reap the immediate child so the kernel doesn't accumulate
	// zombies if containerd later exits. The detached process keeps
	// its own fd on the log file.
	go func() {
		_ = cmd.Wait()
		logFile.Close()
	}()
	return waitForContainerdSock(ctx)
}

// waitForContainerdSock waits up to containerdTimeout for the
// user-containerd socket to appear under state.ContainerdSocket.
func waitForContainerdSock(ctx context.Context) error {
	deadline := time.After(containerdTimeout)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(state.ContainerdSocket); err == nil {
			log.Printf("containerd socket ready: %s", state.ContainerdSocket)
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("waiting for containerd socket: %w", ctx.Err())
		case <-deadline:
			return fmt.Errorf("timed out after %s waiting for containerd socket %s",
				containerdTimeout, state.ContainerdSocket)
		case <-ticker.C:
		}
	}
}

// ---------------------------------------------------------------------------
// CNI plugins
// ---------------------------------------------------------------------------

// CopyCNIPlugins stages the CNI binaries into both legacy
// (/var/lib/cni/bin) and modern (/opt/cni/bin) locations, and drops
// in the EVE-specific eve-bridge binary alongside them.
func CopyCNIPlugins() error {
	log.Printf("copying CNI plugins")
	for _, dir := range []string{CNIBinDir, OptCNIDir} {
		if err := mkdirAll(dir, 0755); err != nil {
			return err
		}
		if err := copyDirContents(CNISrcDir, dir); err != nil {
			return fmt.Errorf("copy CNI plugins to %s: %w", dir, err)
		}
		dst := filepath.Join(dir, "eve-bridge")
		if err := copyFile(eveBridgeSrc, dst); err != nil {
			return fmt.Errorf("copy eve-bridge to %s: %w", dir, err)
		}
	}
	log.Printf("CNI plugins installed")
	return nil
}
