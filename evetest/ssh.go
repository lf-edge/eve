// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest/utils"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"golang.org/x/crypto/ssh"
)

type watchdogWriter struct {
	dst        io.Writer
	activityCh chan struct{}
}

func (w *watchdogWriter) Write(p []byte) (int, error) {
	select {
	case w.activityCh <- struct{}{}:
	default:
	}
	return w.dst.Write(p)
}

// runScriptOnEVEOverSSH executes the provided shellScript on the target EVE device
// over SSH.
func (th *TestHarness) runScriptOnEVEOverSSH(ctx context.Context, devName string,
	shellScript string, stdout, stderr io.Writer,
	stdoutWatchdogTimeout time.Duration) error {

	eveIP, err := th.getReachableEVEAddr(ctx, devName, 22, "")
	if err != nil {
		return err
	}

	keyPEM, err := os.ReadFile("/root/.ssh/eve_rsa")
	if err != nil {
		return fmt.Errorf("failed to read EVE SSH key: %w", err)
	}

	addr := net.JoinHostPort(eveIP, "22")
	auth := ClientCertAuth{KeyPEM: string(keyPEM)}
	return th.runScriptOverSSH(ctx, addr, auth, shellScript,
		stdout, stderr, stdoutWatchdogTimeout)
}

// runScriptOverSSH executes a shell script on a remote host over SSH
// using the Go crypto/ssh client library. It supports username/password and
// client-certificate authentication methods (see AuthMethod).
func (th *TestHarness) runScriptOverSSH(ctx context.Context,
	addr string, auth AuthMethod, script string,
	stdout, stderr io.Writer, stdoutWatchdogTimeout time.Duration) error {

	sshConfig := &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	switch a := auth.(type) {
	case UsernamePasswordAuth:
		sshConfig.User = a.Username
		sshConfig.Auth = []ssh.AuthMethod{ssh.Password(a.Password)}
	case ClientCertAuth:
		signer, err := ssh.ParsePrivateKey([]byte(a.KeyPEM))
		if err != nil {
			return fmt.Errorf("failed to parse client key: %w", err)
		}
		sshConfig.User = "root"
		sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	default:
		return fmt.Errorf("unsupported auth method type %T", auth)
	}

	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("SSH dial to %s failed: %w", addr, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("SSH session creation failed: %w", err)
	}
	defer session.Close()

	session.Stdin = strings.NewReader(script)
	session.Stderr = stderr

	doneCh := make(chan struct{})
	defer close(doneCh)

	if stdoutWatchdogTimeout > 0 {
		activityCh := make(chan struct{}, 1)
		session.Stdout = &watchdogWriter{dst: stdout, activityCh: activityCh}

		go func() {
			timer := time.NewTimer(stdoutWatchdogTimeout)
			defer timer.Stop()
			for {
				select {
				case <-activityCh:
					timer.Reset(stdoutWatchdogTimeout)
				case <-timer.C:
					th.log.Errorf(
						"Killing SSH session to %s due to stdout inactivity", addr)
					_ = session.Signal(ssh.SIGKILL)
					_ = session.Close()
					return
				case <-doneCh:
					return
				}
			}
		}()
	} else {
		session.Stdout = stdout
	}

	// Close the session if the context deadline expires.
	go func() {
		select {
		case <-ctx.Done():
			_ = session.Close()
		case <-doneCh:
		}
	}()

	return session.Run("sh -s")
}

// scpFromEVE copies a file (or, when recursive is true, a directory) from the
// device to a local path. When copying a directory recursively, append "/." to
// the remote path to copy the directory contents rather than the directory itself.
func (th *TestHarness) scpFromEVE(ctx context.Context,
	devName string, remotePath string, localPath string, recursive bool) error {

	eveIP, err := th.getReachableEVEAddr(ctx, devName, 22, "")
	if err != nil {
		return err
	}

	return runSCP(ctx, func(legacy bool) []string {
		args := scpBaseArgs(recursive, legacy)
		return append(args, "root@"+scpHost(eveIP)+":"+scpRemotePath(remotePath, legacy),
			localPath)
	})
}

// scpBaseArgs returns the options common to all scp invocations against EVE.
func scpBaseArgs(recursive, legacy bool) []string {
	args := append([]string{}, utils.EveSSHCommonArgs...)
	if recursive {
		args = append(args, "-r")
	}
	if legacy {
		args = append(args, "-O")
	}
	return append(args, "-i", "/root/.ssh/eve_rsa")
}

// scpRemotePath formats a remote path for scp. Over SFTP the path is passed
// verbatim (no remote shell splits it, so escaping would become part of the
// file name). The legacy protocol (-O) hands it to the remote shell, so shell
// metacharacters have to be escaped. Backslashes are used rather than quotes:
// the scp client matches the file names sent back by the remote scp against
// the last path component of the request as a glob pattern, which honours
// backslash escapes but would see surrounding quotes as part of the name
// ("filename does not match request").
func scpRemotePath(remotePath string, legacy bool) string {
	if !legacy {
		return remotePath
	}
	var b strings.Builder
	for _, r := range remotePath {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("/._-,:@%+=#", r)) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// runSCP runs scp over SFTP (the OpenSSH 9.x default) and, if that fails,
// retries once with the legacy SCP protocol (-O). EVE 14.5-stable ships an
// sshd whose "Subsystem sftp" path does not exist, so SFTP never works there
// ("scp: Connection closed"), while the legacy protocol only needs the scp
// binary on the device.
func runSCP(ctx context.Context, buildArgs func(legacy bool) []string) error {
	run := func(legacy bool) error {
		cmd := exec.CommandContext(ctx, "scp", buildArgs(legacy)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			if msg := strings.TrimSpace(stderr.String()); msg != "" {
				return fmt.Errorf("%w: %s", err, msg)
			}
			return err
		}
		return nil
	}
	sftpErr := run(false)
	if sftpErr == nil || ctx.Err() != nil {
		return sftpErr
	}
	if err := run(true); err != nil {
		return fmt.Errorf("%w (SFTP attempt: %v)", err, sftpErr)
	}
	return nil
}

// scpHost formats a device address for use in an scp target: an IPv6 address
// must be bracketed, or scp takes everything after its first colon as the
// path.
func scpHost(eveIP string) string {
	if strings.Contains(eveIP, ":") {
		return "[" + eveIP + "]"
	}
	return eveIP
}

// scpToEVE copies a file (or, when recursive is true, a directory) from a
// local path to the device.
func (th *TestHarness) scpToEVE(ctx context.Context,
	devName string, localPath string, remotePath string, recursive bool) error {

	eveIP, err := th.getReachableEVEAddr(ctx, devName, 22, "")
	if err != nil {
		return err
	}

	return runSCP(ctx, func(legacy bool) []string {
		args := scpBaseArgs(recursive, legacy)
		return append(args, localPath,
			"root@"+scpHost(eveIP)+":"+scpRemotePath(remotePath, legacy))
	})
}

// getReachableEVEAddr finds a reachable IP for the given device at the specified
// target port. If interfaceName is non-empty, only IPs from that interface are
// considered; otherwise all device IPs are tried.
// When interfaceName is empty, IPs from device info are tried first. If that
// fails (e.g. device info not yet available), IPs discovered via SDN are tried
// as a fallback.
func (th *TestHarness) getReachableEVEAddr(
	ctx context.Context, devName string, targetPort uint32,
	interfaceName string) (string, error) {

	portStr := fmt.Sprintf("%d", targetPort)

	// Collect IPs from device info.
	if interfaceName != "" && !th.isDeviceOnboarded(devName) {
		return "", fmt.Errorf("unknown device %q", devName)
	}
	var eveIPs []string
	if th.isDeviceOnboarded(devName) {
		dev := GetEdgeDevice(devName)
		for _, ip := range dev.GetDeviceIPAddress(interfaceName) {
			eveIPs = append(eveIPs, ip.String())
		}
	}

	if interfaceName != "" && len(eveIPs) == 0 {
		return "", fmt.Errorf(
			"no IP addresses found for device %q interface %q",
			devName, interfaceName)
	}

	if len(eveIPs) > 0 {
		addrs := make([]string, len(eveIPs))
		for i, ip := range eveIPs {
			addrs[i] = net.JoinHostPort(ip, portStr)
		}
		addr, err := th.probeReachableAddr(ctx, addrs)
		if err == nil {
			host, _, _ := net.SplitHostPort(addr)
			return host, nil
		}
	}

	// Interface was specified — do not fall back to SDN discovery.
	if interfaceName != "" {
		return "", fmt.Errorf(
			"no reachable endpoint for device %q interface %q port %d",
			devName, interfaceName, targetPort)
	}

	// Fallback: discover IPs via SDN (covers pre-onboarding or info not yet available).
	th.log.Debugf("Falling back to SDN-based IP discovery for device %q", devName)
	discoveredIPs, err := th.discoverEVEIPs(ctx, devName)
	if err != nil {
		return "", err
	}

	// Only try IPs that were not already probed via device info.
	var newAddrs []string
	for _, ip := range discoveredIPs {
		if !generics.ContainsItem(eveIPs, ip) {
			newAddrs = append(newAddrs, net.JoinHostPort(ip, portStr))
		}
	}
	if len(newAddrs) == 0 {
		return "", fmt.Errorf(
			"no reachable endpoint for device %q port %d "+
				"(SDN discovery found no additional IPs)", devName, targetPort)
	}

	addr, err := th.probeReachableAddr(ctx, newAddrs)
	if err != nil {
		return "", err
	}

	host, _, _ := net.SplitHostPort(addr)
	return host, nil
}

// probeReachableAddr tries each address in addrs (host:port format) with up to
// 3 TCP dial attempts and returns the first reachable address.
func (th *TestHarness) probeReachableAddr(ctx context.Context,
	addrs []string) (string, error) {
	const maxRetries = 3
	for _, addr := range addrs {
		for attempt := 1; attempt <= maxRetries; attempt++ {
			dialer := net.Dialer{}
			connCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			conn, dialErr := dialer.DialContext(connCtx, "tcp", addr)
			cancel()
			if dialErr != nil {
				th.log.Errorf(
					"Attempt %d/%d: failed to connect to endpoint %s: %v",
					attempt, maxRetries, addr, dialErr,
				)
				continue
			}
			_ = conn.Close()
			th.log.Debugf("Connected to endpoint %s on attempt %d/%d",
				addr, attempt, maxRetries)
			return addr, nil
		}
	}
	return "", fmt.Errorf("no reachable endpoint among %v", addrs)
}

// discoverEVEIPs discovers IP addresses of the given EVE device by querying SDN
// using the MAC addresses of its network ports.
// Returns all successfully discovered IPs or an error if none were found.
func (th *TestHarness) discoverEVEIPs(
	ctx context.Context, devName string) (eveIPs []string, err error) {
	th.netModelM.Lock()
	defer th.netModelM.Unlock()

	sdnKeyPEM, err := os.ReadFile("/root/.ssh/sdn_rsa")
	if err != nil {
		return nil, fmt.Errorf("failed to read SDN SSH key: %w", err)
	}
	sdnAddr := net.JoinHostPort(sdnTunVMIPv4.String(), "22")
	sdnAuth := ClientCertAuth{KeyPEM: string(sdnKeyPEM)}

	if th.netModel == nil {
		return nil, fmt.Errorf("network model not applied, "+
			"therefore cannot discover IP of device %q", devName)
	}

	for _, port := range th.netModel.Ports {
		if port.EveDeviceName != devName {
			continue
		}

		macAddr := port.EveMacAddress
		script := "/bin/get-eve-ip.sh " + macAddr
		var stdoutBuf, stderrBuf bytes.Buffer
		err := th.runScriptOverSSH(ctx, sdnAddr, sdnAuth, script,
			&stdoutBuf, &stderrBuf, 0)
		if err != nil {
			th.log.Warnf("Failed to detect EVE IP for device %q (port %q): %v",
				devName, port.LogicalLabel, err)
			continue
		}

		// get-eve-ip.sh can return multiple IPs, separated by a newline
		ips := strings.Split(stdoutBuf.String(), "\n")

		foundIP := false
		for _, ipStr := range ips {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr == "" {
				continue
			}

			ip := net.ParseIP(ipStr)
			if ip == nil {
				th.log.Warnf(
					"Ignoring invalid EVE IP %q for device %q (port %q, MAC %s)",
					ipStr, devName, port.LogicalLabel, macAddr,
				)
				continue
			}

			// Filter non-routable addresses
			if ip.IsLinkLocalUnicast() || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}

			foundIP = true
			th.log.Debugf(
				"Detected EVE IP %s for device %q (port %q, MAC %s)",
				ip, devName, port.LogicalLabel, macAddr,
			)
			eveIPs = append(eveIPs, ipStr)
		}

		if !foundIP {
			th.log.Warnf(
				"No EVE IP returned for device %q (port %q, MAC %s)",
				devName, port.LogicalLabel, macAddr,
			)
		}
	}

	if len(eveIPs) == 0 {
		err = fmt.Errorf("failed to detect any IP address for EVE device %q",
			devName)
		th.log.Error(err)
		return nil, err
	}
	return eveIPs, nil
}
