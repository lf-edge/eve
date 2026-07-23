// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package k3s

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Supervisor lifecycle tuning. Test code may shrink these via
// t.Cleanup; production callers MUST NOT mutate them.
var (
	stopGracePeriod  = 15 * time.Second
	portPollAttempts = 5
	portPollInterval = 2 * time.Second
	defaultK3sArgs   = []string{"server"}
)

const (
	k3sAPIServerPort  = 6443
	k3sSupervisorPort = 6444
)

// Substrings used by the post-stop orphan sweep. cmdlineMatchesOrphan
// short-circuits on excludes before checking matches. Lowercase to
// signal "package-private constants, do not mutate".
var (
	orphanCmdlineMatches = []string{
		"k3s server",
		"k3s init",
		"k3s-server",
		"/usr/bin/k3s",
	}
	orphanCmdlineExcludes = []string{
		"kube-init",
	}
)

// ErrPortsStillBound is returned by Stop when the k3s API or
// supervisor port is still listening after portPollAttempts. A
// follow-up Start will fail with "address in use"; surfacing this
// here lets the FSM preempt with a more actionable error.
var ErrPortsStillBound = errors.New("k3s ports still bound after Stop")

// ErrAlreadyRunning is returned by Start when a previous Start has
// not been balanced by Stop.
var ErrAlreadyRunning = errors.New("supervisor already running")

// Supervisor manages the k3s server process lifecycle: starting it
// under a fresh process group, capturing exit via Done()+LastExit(),
// stopping it with SIGTERM→SIGKILL escalation, killing reparented
// descendants, waiting for ports to free, and running pre-restart
// hooks when invoked.
//
// Concurrency: the read-only accessors (IsRunning, K3sPID, Done,
// LastExit) may be called from any goroutine. Start, Stop, and
// RunHooks MUST be serialized by the caller — they are not safe to
// invoke concurrently with each other.
type Supervisor struct {
	k3sBinary string
	k3sArgs   []string
	logFile   string
	hooksDir  string
	pidFile   string

	mu       sync.Mutex
	k3sCmd   *exec.Cmd     // nil iff no live k3s process
	done     chan struct{} // closed by wait goroutine on process exit
	lastExit error         // exit error captured before done is closed
}

// SupervisorOption configures a Supervisor at construction time.
type SupervisorOption func(*Supervisor)

// WithK3sBinary overrides the k3s binary path the supervisor
// will exec. Default is K3sSymlink.
func WithK3sBinary(path string) SupervisorOption {
	return func(s *Supervisor) { s.k3sBinary = path }
}

// WithK3sArgs overrides the argv passed to the k3s binary. The
// slice is copied so callers can reuse / mutate the original.
func WithK3sArgs(args []string) SupervisorOption {
	return func(s *Supervisor) { s.k3sArgs = append([]string(nil), args...) }
}

// WithLogFile overrides the path k3s stdout/stderr is appended to.
func WithLogFile(path string) SupervisorOption {
	return func(s *Supervisor) { s.logFile = path }
}

// WithHooksDir overrides the directory the supervisor scans for
// pre-restart hook scripts in RunHooks.
func WithHooksDir(path string) SupervisorOption {
	return func(s *Supervisor) { s.hooksDir = path }
}

// WithPidFile overrides the file path the supervisor writes the
// running k3s PID to.
func WithPidFile(path string) SupervisorOption {
	return func(s *Supervisor) { s.pidFile = path }
}

// NewSupervisor returns a Supervisor with package defaults applied
// before any caller options.
//
// Defaults: k3s binary = K3sSymlink ("/usr/bin/k3s"), args = ["server"],
// log = supervisorLogFile, hooks dir = supervisorHooksDir, pid file =
// supervisorPidFile.
func NewSupervisor(opts ...SupervisorOption) *Supervisor {
	s := &Supervisor{
		k3sBinary: K3sSymlink,
		k3sArgs:   append([]string(nil), defaultK3sArgs...),
		logFile:   supervisorLogFile,
		hooksDir:  supervisorHooksDir,
		pidFile:   supervisorPidFile,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Start launches the k3s process. Returns ErrAlreadyRunning if a
// previous Start was not balanced by Stop.
func (s *Supervisor) Start() error {
	s.mu.Lock()
	if s.k3sCmd != nil {
		s.mu.Unlock()
		return ErrAlreadyRunning
	}
	s.mu.Unlock()

	if err := os.MkdirAll(s.hooksDir, 0755); err != nil {
		// Hooks are best-effort; don't fail Start if the dir can't
		// be created. RunHooks will simply find nothing to run.
		log.Printf("failed to create hooks dir %s: %v", s.hooksDir, err)
	}
	return s.startK3s()
}

// Stop terminates the k3s process and ALL its descendants, waits up
// to stopGracePeriod for the main process to exit, escalates to
// SIGKILL on the full tree if needed, sweeps orphaned descendants
// that may have been reparented to us, removes the pid file, and
// waits for the API server ports to be released.
//
// Returns ErrPortsStillBound if the k3s ports are still listening
// after the port-poll budget elapses — a follow-up Start would fail
// with "address in use".
func (s *Supervisor) Stop() error {
	return s.stopK3s()
}

// Done returns a channel that is closed when the k3s process has
// exited (either naturally or after Stop). The channel is replaced
// on each Start; capture it BEFORE Start returns if you need to
// avoid a race with a fast-exit. After close, LastExit returns the
// exit error.
//
// A Supervisor that has never been started returns a nil channel,
// which never closes (and is never selectable).
func (s *Supervisor) Done() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.done
}

// LastExit returns the most recent k3s exit error, or nil if k3s
// exited cleanly. Returns nil before the first exit; callers should
// gate the call on Done having closed.
func (s *Supervisor) LastExit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastExit
}

// IsRunning reports whether the k3s process is still alive. The
// wait goroutine clears k3sCmd under mu when the process exits, so
// IsRunning returns false reliably after Done has closed (no probe
// of a reaped PID).
func (s *Supervisor) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.k3sCmd != nil
}

// K3sPID returns the current k3s process ID, or 0 if k3s is not
// running.
func (s *Supervisor) K3sPID() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.k3sCmd == nil || s.k3sCmd.Process == nil {
		return 0
	}
	return s.k3sCmd.Process.Pid
}

// RunHooks executes every executable file in the hooks directory in
// lexical order. Hook failures are logged but do not abort the
// sequence — these are pre-restart cleanups invoked from explicit
// FSM-driven restarts only (not crash recovery).
func (s *Supervisor) RunHooks() {
	entries, err := os.ReadDir(s.hooksDir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("failed to read hooks dir %s: %v", s.hooksDir, err)
		}
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			log.Printf("failed to stat hook %s: %v", entry.Name(), err)
			continue
		}
		if info.Mode()&0111 == 0 {
			continue
		}
		hookPath := filepath.Join(s.hooksDir, entry.Name())
		log.Printf("running hook: %s", hookPath)
		cmd := exec.Command(hookPath)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			log.Printf("hook %s failed: %v (continuing)", hookPath, err)
		}
	}
}

// startK3s launches the k3s binary in a fresh process group, wires
// up logging, and starts the wait goroutine that signals exit via
// done + lastExit.
func (s *Supervisor) startK3s() error {
	if dir := filepath.Dir(s.logFile); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("create log dir %s: %w", dir, err)
		}
	}
	lf, err := os.OpenFile(s.logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file %s: %w", s.logFile, err)
	}

	// Remove any stale pid file from a previous failed Start before
	// we promise the caller a clean start.
	s.cleanupPidFile()

	// Remove the stale flannel.1 VXLAN device before k3s comes up.
	// Without this, flannel v0.27.4 hits a nil-pointer SIGSEGV in
	// watchVXLANDevice during a k3s transition. The next flannel
	// (re-)creates the device with a clean state. See upstream
	// commit 2c417d5fe.
	removeStaleFlannel()

	// Ensure the host-local CNI plugin is on PATH. k3s v1.34+
	// validates CNI plugins via exec.LookPath; without this
	// /usr/bin shim the validation fails and k3s never reaches
	// Ready. See ensureHostLocalInPath in install.go (upstream
	// commit 75fe3cd94). Called on every Start so a restart that
	// skipped INSTALLING still gets the link.
	if err := ensureHostLocalInPath(); err != nil {
		log.Printf("WARNING: ensure host-local on PATH: %v", err)
	}

	cmd := exec.Command(s.k3sBinary, s.k3sArgs...)
	cmd.Stdout = lf
	cmd.Stderr = lf
	// Setpgid so SIGTERM to -pid catches the whole group on Stop,
	// reaching children that didn't create their own process group.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		_ = lf.Close()
		return fmt.Errorf("start k3s: %w", err)
	}

	done := make(chan struct{})
	s.mu.Lock()
	s.k3sCmd = cmd
	s.done = done
	s.lastExit = nil
	s.mu.Unlock()

	pid := cmd.Process.Pid
	log.Printf("k3s started, pid=%d, args=%s", pid, strings.Join(s.k3sArgs, " "))

	if s.pidFile != "" {
		body := strconv.Itoa(pid) + "\n"
		if err := os.WriteFile(s.pidFile, []byte(body), 0644); err != nil {
			// External monitoring keys off this file; surface the
			// inconsistency clearly so an operator can act.
			log.Printf("WARNING: pid file %s write failed: %v "+
				"(external monitoring may report k3s as down)",
				s.pidFile, err)
		}
	}

	go func() {
		waitErr := cmd.Wait()
		if cerr := lf.Close(); cerr != nil {
			log.Printf("close log file %s: %v", s.logFile, cerr)
		}
		s.mu.Lock()
		s.lastExit = waitErr
		s.k3sCmd = nil
		s.mu.Unlock()
		close(done)
	}()
	return nil
}

// stopK3s terminates k3s and its tree, then waits for ports to free.
func (s *Supervisor) stopK3s() error {
	s.mu.Lock()
	cmd := s.k3sCmd
	done := s.done
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}
	pid := cmd.Process.Pid
	log.Printf("stopping k3s (pid %d): SIGTERM to process group + descendants", pid)

	// SIGTERM the process group plus every descendant discovered via
	// /proc walk. The /proc walk catches children that created their
	// own process groups.
	killGroup(pid, syscall.SIGTERM)
	for _, dpid := range findDescendants(pid) {
		killOne(dpid, syscall.SIGTERM)
	}

	if done != nil {
		select {
		case <-done:
			log.Printf("k3s main process exited after SIGTERM")
		case <-time.After(stopGracePeriod):
			log.Printf("k3s did not exit in %v; SIGKILL to tree", stopGracePeriod)
			killGroup(pid, syscall.SIGKILL)
			// Re-walk: descendants that set their own pgid AND were
			// spawned during the grace window aren't reached by the
			// pgid kill alone.
			for _, dpid := range findDescendants(pid) {
				killOne(dpid, syscall.SIGKILL)
			}
			<-done
		}
	}

	s.killOrphanedK3sProcesses()

	s.cleanupPidFile()

	// Symmetric with the pre-start removal in startK3s: drop
	// flannel.1 so the next k3s start sees a clean network
	// namespace. See upstream commit 2c417d5fe.
	removeStaleFlannel()

	return s.waitPortsReleased()
}

// removeStaleFlannel deletes the flannel.1 VXLAN device if it
// exists. A leftover device from a previous k3s instance triggers
// a nil-pointer SIGSEGV in flannel v0.27.4's watchVXLANDevice
// during a transition. The next flannel (re-)creates the device
// with the right state. Errors are intentionally swallowed:
// "device not present" is the common case and the shell version
// used `ip link del flannel.1 2>/dev/null || true`.
func removeStaleFlannel() {
	cmd := exec.Command("ip", "link", "del", "flannel.1")
	_ = cmd.Run()
}

// cleanupPidFile removes the pid file if present. Missing-file is
// ignored; other errors are logged.
func (s *Supervisor) cleanupPidFile() {
	if s.pidFile == "" {
		return
	}
	if err := os.Remove(s.pidFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Printf("warning: remove pid file %s: %v", s.pidFile, err)
	}
}

// killGroup sends sig to the entire process group identified by pid.
// ESRCH is expected (the process already exited); other errnos are
// real bugs and get logged.
func killGroup(pid int, sig syscall.Signal) {
	if err := syscall.Kill(-pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Printf("kill -%d %v: %v", pid, sig, err)
	}
}

// killOne sends sig to a single pid. ESRCH is expected after exit.
func killOne(pid int, sig syscall.Signal) {
	if err := syscall.Kill(pid, sig); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Printf("kill %d %v: %v", pid, sig, err)
	}
}

// findDescendants returns all descendant PIDs of root via procRoot.
// Result is breadth-first (children before grandchildren).
//
// Race-aware: descendants spawned between readdir and SIGTERM may
// be missed, but the process-group kill catches them by virtue of
// the inherited pgid. Logs (instead of silently returning nil) when
// procRoot is unreadable — that should never happen in production
// and points at a misrouted procRoot var.
func findDescendants(root int) []int {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		log.Printf("warning: read %s: %v (descendant scan skipped)", procRoot, err)
		return nil
	}
	children := make(map[int][]int)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if ppid := readPPID(pid); ppid > 0 {
			children[ppid] = append(children[ppid], pid)
		}
	}
	var result []int
	queue := children[root]
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		result = append(result, pid)
		queue = append(queue, children[pid]...)
	}
	return result
}

// readPPID reads the parent PID from <procRoot>/<pid>/stat. ENOENT
// is expected (race with process exit); other errors are logged.
//
// /proc/[pid]/stat layout is `pid (comm) state ppid ...` where comm
// may contain spaces and parentheses, so we anchor on the LAST `)`
// and read the second field after it.
func readPPID(pid int) int {
	path := fmt.Sprintf("%s/%d/stat", procRoot, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			log.Printf("warning: read %s: %v", path, err)
		}
		return 0
	}
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx < 0 || idx+2 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[idx+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0
	}
	return ppid
}

// killOrphanedK3sProcesses scans procRoot for k3s-related cmdlines
// not belonging to us and SIGKILLs them. Catches descendants
// reparented away from the supervisor between SIGTERM and SIGKILL.
//
// The cmdline match is deliberately loose — anything containing
// "k3s server" / "k3s init" / "k3s-server" / "/usr/bin/k3s" (and
// not "kube-init") is a kill target. False positives are unlikely
// in a kube container; false negatives (wrapper scripts that
// rewrite argv[0]) are accepted.
func (s *Supervisor) killOrphanedK3sProcesses() {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		log.Printf("warning: read %s: %v (orphan sweep skipped)", procRoot, err)
		return
	}
	myPid := os.Getpid()
	killed := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		if pid == myPid || pid == 1 {
			continue
		}
		cmdlinePath := fmt.Sprintf("%s/%d/cmdline", procRoot, pid)
		cmdline, err := os.ReadFile(cmdlinePath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Printf("warning: read %s: %v", cmdlinePath, err)
			}
			continue
		}
		// /proc cmdline uses NUL as the argv separator.
		normalized := strings.ReplaceAll(string(cmdline), "\x00", " ")
		if !cmdlineMatchesOrphan(normalized) {
			continue
		}
		log.Printf("killing orphaned k3s process: pid=%d cmd=%s",
			pid, truncate(normalized, 80))
		killOne(pid, syscall.SIGKILL)
		killed++
	}
	if killed > 0 {
		log.Printf("killed %d orphaned k3s processes", killed)
	}
}

func cmdlineMatchesOrphan(cmdline string) bool {
	for _, excl := range orphanCmdlineExcludes {
		if strings.Contains(cmdline, excl) {
			return false
		}
	}
	for _, match := range orphanCmdlineMatches {
		if strings.Contains(cmdline, match) {
			return true
		}
	}
	return false
}

// waitPortsReleased polls until the k3s API and supervisor ports are
// both free. Returns ErrPortsStillBound if the budget elapses while
// either port remains bound, so the FSM can preempt the follow-up
// Start's "address in use" failure with a more actionable error.
func (s *Supervisor) waitPortsReleased() error {
	for i := 0; i < portPollAttempts; i++ {
		bound, err := anyPortBound(k3sAPIServerPort, k3sSupervisorPort)
		if err != nil {
			// /proc/net/tcp unreadable: surface the error rather
			// than pretending the port is free (which would let a
			// follow-up Start blindly fail with EADDRINUSE).
			return fmt.Errorf("check k3s ports: %w", err)
		}
		if !bound {
			return nil
		}
		log.Printf("waiting for ports %d/%d to be released (%d/%d)",
			k3sAPIServerPort, k3sSupervisorPort, i+1, portPollAttempts)
		time.Sleep(portPollInterval)
	}
	return fmt.Errorf("%w (ports %d, %d)",
		ErrPortsStillBound, k3sAPIServerPort, k3sSupervisorPort)
}

// anyPortBound reports whether any of ports has a listener on the
// IPv4 OR IPv6 TCP stack. Reads procRoot/net/tcp and procRoot/net/tcp6
// and matches the column-aware local-address field (not a substring).
func anyPortBound(ports ...int) (bool, error) {
	for _, fam := range []string{"tcp", "tcp6"} {
		path := filepath.Join(procRoot, "net", fam)
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// tcp6 may be absent on an IPv6-disabled kernel.
				continue
			}
			return false, fmt.Errorf("read %s: %w", path, err)
		}
		if hasListener(data, ports) {
			return true, nil
		}
	}
	return false, nil
}

// hasListener scans a /proc/net/tcp* dump and returns true if any
// row has a local_address port matching one of ports. The format is:
//
//	  sl  local_address  rem_address  st  ...
//	   0: 00000000:1F40 00000000:0000 0A  ...
//
// Each port lookup compares against the hex port half of local_address
// (field index 1), so it doesn't false-match on rem_address ports or
// on a port hex literal appearing elsewhere in the line.
func hasListener(data []byte, ports []int) bool {
	target := make(map[string]struct{}, len(ports))
	for _, p := range ports {
		target[fmt.Sprintf("%04X", p)] = struct{}{}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Scan() // discard header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		// local_address is "IP_HEX:PORT_HEX"
		i := strings.LastIndex(fields[1], ":")
		if i < 0 {
			continue
		}
		if _, ok := target[fields[1][i+1:]]; ok {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
