// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve/evetest/logger"
	"github.com/luthermonson/go-proxmox"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

const (
	// proxmoxSSHPort is where sshd listens on the PVE host.
	proxmoxSSHPort = "22"
	// proxmoxSSHDialTimeout bounds connecting and authenticating to the host.
	proxmoxSSHDialTimeout = 30 * time.Second
)

// proxmoxQMPSocketPath is the Unix socket of a VM's evetest QMP monitor (see
// buildVMOptions), in PVE's runtime directory next to PVE's own <vmid>.qmp.
// PVE removes only its own files there when a VM stops; a stale socket of
// ours is unlinked by QEMU when the VM starts again.
func proxmoxQMPSocketPath(vmID int) string {
	return fmt.Sprintf("/var/run/qemu-server/%d.evqmp", vmID)
}

// sshConnect returns the provider's SSH connection to the PVE host, dialing it
// on first use or after sshDrop. The broker runs in a VM and cannot open a
// Unix socket on the host itself; sshd does that on its behalf (Client.Dial
// with "unix", OpenSSH's direct-streamlocal channel). It logs in as root with
// the root@pam password the API uses. The host key is not verified, in line
// with TLSSkipVerify for the API.
func (p *ProxmoxProvider) sshConnect(ctx context.Context) (*ssh.Client, error) {
	p.sshMutex.Lock()
	defer p.sshMutex.Unlock()
	if p.sshClient != nil {
		return p.sshClient, nil
	}

	apiURL, err := url.Parse(p.conf.APIURL)
	if err != nil || apiURL.Hostname() == "" {
		return nil, fmt.Errorf("cannot derive the PVE host from the API URL %q: %v",
			p.conf.APIURL, err)
	}
	addr := net.JoinHostPort(apiURL.Hostname(), proxmoxSSHPort)
	dialCtx, cancel := context.WithTimeout(ctx, proxmoxSSHDialTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the PVE host at %s over SSH: %w",
			addr, err)
	}
	sshConfig := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password(p.conf.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // see doc comment
		Timeout:         proxmoxSSHDialTimeout,
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("SSH handshake with the PVE host at %s failed (root login "+
			"with the root@pam password must be allowed): %w", addr, err)
	}
	p.sshClient = ssh.NewClient(sshConn, chans, reqs)
	return p.sshClient, nil
}

// sshDrop closes the SSH connection after a failure so that sshConnect
// redials. A connection newer than the failed one is left alone.
func (p *ProxmoxProvider) sshDrop(failed *ssh.Client) {
	log := logger.FromContext(context.Background())

	p.sshMutex.Lock()
	defer p.sshMutex.Unlock()
	if failed != nil && p.sshClient == failed {
		err := failed.Close()
		if err != nil {
			log.Infof("closing ssh client to %s failed: %v", failed.RemoteAddr().String(), err)
		}
		p.sshClient = nil
	}
}

// deviceQMP returns the QMP client of the device's evetest monitor, connecting
// on first use. Nobody else connects to that monitor, so the connection is
// kept for as long as the VM runs.
func (p *ProxmoxProvider) deviceQMP(ctx context.Context, dev *proxmoxDevice) (*qmpClient, error) {
	p.devMutex.Lock()
	qmp := dev.qmpClient
	p.devMutex.Unlock()
	if qmp != nil {
		return qmp, nil
	}

	log := logger.FromContext(ctx)
	sshClient, err := p.sshConnect(ctx)
	if err != nil {
		return nil, err
	}
	socketPath := proxmoxQMPSocketPath(dev.vmID)
	conn, err := sshClient.Dial("unix", socketPath)
	if err != nil {
		// A refused channel means sshd could not open the socket, typically
		// because the VM is not running; anything else is the SSH connection.
		var openErr *ssh.OpenChannelError
		if !errors.As(err, &openErr) {
			p.sshDrop(sshClient)
		}
		return nil, fmt.Errorf("failed to open QMP socket %s of device %q on the PVE "+
			"host (is the device running?): %w", socketPath, dev.name, err)
	}
	qmp, err = newQMPClient(ctx, log, conn)
	if err != nil {
		return nil, fmt.Errorf("QMP handshake with device %q failed: %w", dev.name, err)
	}

	p.devMutex.Lock()
	defer p.devMutex.Unlock()
	if dev.qmpClient != nil {
		// A concurrent ExecuteQMP connected first; keep that connection.
		_ = qmp.close()
		return dev.qmpClient, nil
	}
	dev.qmpClient = qmp
	return qmp, nil
}

// dropDeviceQMPLocked forgets the device's QMP connection, once the VM stopped
// or the connection failed; the next ExecuteQMP reconnects. Caller holds
// devMutex.
func (p *ProxmoxProvider) dropDeviceQMPLocked(dev *proxmoxDevice) {
	if dev.qmpClient != nil {
		_ = dev.qmpClient.close()
		dev.qmpClient = nil
	}
}

// ExecuteQMP runs one QMP command on the VM through its evetest monitor.
func (p *ProxmoxProvider) ExecuteQMP(ctx context.Context, name, execute string,
	arguments json.RawMessage) (json.RawMessage, error) {
	dev, err := p.lookupDevice(name)
	if err != nil {
		return nil, err
	}
	qmp, err := p.deviceQMP(ctx, dev)
	if err != nil {
		return nil, err
	}
	out, err := qmp.executeRaw(ctx, execute, arguments)
	if err != nil {
		var qmpErr *QMPError
		if !errors.As(err, &qmpErr) {
			// Not a reply from QEMU: the connection is gone, e.g. because the
			// VM stopped. Reconnect on the next call.
			p.devMutex.Lock()
			if dev.qmpClient == qmp {
				p.dropDeviceQMPLocked(dev)
			}
			p.devMutex.Unlock()
		}
		return nil, err
	}
	return out, nil
}

// scratchUploadName is the file name of a scratch image on the import storage.
func scratchUploadName(dev *proxmoxDevice, imageName string) string {
	return fmt.Sprintf("%s-scratch-%s.raw", prefixedName(dev.name), imageName)
}

// CreateScratchImage uploads a sparse raw image to the import storage, the
// way uploadFirmware ships files that QEMU opens live, and returns its path
// on the PVE host. The upload transfers the image's full size, which is why
// the broker caps it.
func (p *ProxmoxProvider) CreateScratchImage(ctx context.Context, name, imageName string,
	sizeBytes uint64) (string, error) {
	log := logger.FromContext(ctx)
	if err := ValidateScratchImageName(imageName); err != nil {
		return "", err
	}
	dev, err := p.lookupDevice(name)
	if err != nil {
		return "", err
	}

	// Reserve the name first, so that two concurrent creates cannot both
	// upload an image under it.
	p.devMutex.Lock()
	if dev.scratchVolIDs == nil {
		dev.scratchVolIDs = make(map[string]string)
	}
	if _, exists := dev.scratchVolIDs[imageName]; exists {
		p.devMutex.Unlock()
		return "", fmt.Errorf("scratch image %q of device %q already exists", imageName, name)
	}
	dev.scratchVolIDs[imageName] = ""
	p.devMutex.Unlock()
	unreserve := func() {
		p.devMutex.Lock()
		delete(dev.scratchVolIDs, imageName)
		p.devMutex.Unlock()
	}

	tmpFile, err := os.CreateTemp("", "evetest-scratch-*.raw")
	if err != nil {
		unreserve()
		return "", fmt.Errorf("failed to create a temporary scratch image: %w", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()
	if err := tmpFile.Truncate(int64(sizeBytes)); err != nil {
		_ = tmpFile.Close()
		unreserve()
		return "", fmt.Errorf("failed to size the temporary scratch image: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		unreserve()
		return "", fmt.Errorf("failed to close the temporary scratch image: %w", err)
	}

	node, err := p.client.Node(ctx, p.conf.Node)
	if err != nil {
		unreserve()
		return "", fmt.Errorf("failed to get Proxmox node %q: %w", p.conf.Node, err)
	}
	basePath, err := p.importStoragePath(ctx)
	if err != nil {
		unreserve()
		return "", err
	}
	storage, err := p.getStorageWithRetry(ctx, log, node, p.conf.ImportStorage)
	if err != nil {
		unreserve()
		return "", fmt.Errorf("failed to get import storage %q: %w", p.conf.ImportStorage, err)
	}
	uploadName := scratchUploadName(dev, imageName)
	task, err := p.uploadWithRetry(ctx, log, storage, tmpFile.Name(), uploadName)
	if err != nil {
		unreserve()
		return "", fmt.Errorf("failed to upload scratch image %q to storage %q: %w",
			imageName, p.conf.ImportStorage, err)
	}
	if err := waitTask(ctx, task); err != nil {
		unreserve()
		return "", fmt.Errorf("failed waiting for the upload of scratch image %q: %w",
			imageName, err)
	}

	volID := fmt.Sprintf("%s:import/%s", p.conf.ImportStorage, uploadName)
	p.devMutex.Lock()
	dev.scratchVolIDs[imageName] = volID
	p.devMutex.Unlock()
	hostPath := filepath.Join(basePath, "import", uploadName)
	log.Infof("Uploaded scratch image %q (%d bytes) for device %q to %s",
		imageName, sizeBytes, name, hostPath)
	return hostPath, nil
}

// DeleteScratchImage removes an image created by CreateScratchImage from the
// import storage.
func (p *ProxmoxProvider) DeleteScratchImage(ctx context.Context, name, imageName string) error {
	log := logger.FromContext(ctx)
	if err := ValidateScratchImageName(imageName); err != nil {
		return err
	}
	dev, err := p.lookupDevice(name)
	if err != nil {
		return err
	}
	node, err := p.client.Node(ctx, p.conf.Node)
	if err != nil {
		return fmt.Errorf("failed to get Proxmox node %q: %w", p.conf.Node, err)
	}

	p.devMutex.Lock()
	volID, ok := dev.scratchVolIDs[imageName]
	if ok && volID != "" {
		delete(dev.scratchVolIDs, imageName)
	}
	p.devMutex.Unlock()
	if !ok {
		return fmt.Errorf("device %q has no scratch image %q", name, imageName)
	}
	if volID == "" {
		return fmt.Errorf("scratch image %q of device %q is still being created",
			imageName, name)
	}

	if err := p.deleteImportVolume(ctx, log, node, volID); err != nil {
		// Keep it on the books so that the device's teardown retries.
		p.devMutex.Lock()
		dev.scratchVolIDs[imageName] = volID
		p.devMutex.Unlock()
		return err
	}
	log.Infof("Removed scratch image %q of device %q", imageName, name)
	return nil
}

// volumesToRemove lists the import-storage volumes the device still holds at
// teardown: custom firmware and any scratch images the test did not delete.
func (p *ProxmoxProvider) volumesToRemove(dev *proxmoxDevice) []string {
	p.devMutex.Lock()
	defer p.devMutex.Unlock()
	volIDs := append([]string{}, dev.firmwareVolIDs...)
	for _, volID := range dev.scratchVolIDs {
		if volID != "" {
			volIDs = append(volIDs, volID)
		}
	}
	return volIDs
}

// deleteImportVolume removes one import-storage volume, reporting failure to
// the caller (unlike the best-effort deleteImportVolumes used at teardown).
func (p *ProxmoxProvider) deleteImportVolume(ctx context.Context, log *logrus.Entry,
	node *proxmox.Node, volID string) error {
	storage, err := p.getStorageWithRetry(ctx, log, node, p.conf.ImportStorage)
	if err != nil {
		return fmt.Errorf("failed to get import storage %q: %w", p.conf.ImportStorage, err)
	}
	task, err := storage.DeleteContent(ctx, volID)
	if err != nil {
		return fmt.Errorf("failed to delete import volume %q: %w", volID, err)
	}
	if err := waitTask(ctx, task); err != nil {
		return fmt.Errorf("failed waiting for the deletion of import volume %q: %w", volID, err)
	}
	return nil
}
