// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lf-edge/eve/evetest/logger"
)

// ExecuteQMP runs one QMP command on the device's QEMU process, through the
// connection PowerOnDevice established.
func (p *QemuProvider) ExecuteQMP(ctx context.Context, name, execute string,
	arguments json.RawMessage) (json.RawMessage, error) {
	p.mutex.Lock()
	dev, ok := p.devices[name]
	var qmp *qmpClient
	if ok {
		qmp = dev.qmpClient
	}
	p.mutex.Unlock()
	if !ok {
		return nil, fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
	}
	if qmp == nil {
		return nil, fmt.Errorf("device %q is not running", name)
	}
	return qmp.executeRaw(ctx, execute, arguments)
}

// scratchImagePath is where CreateScratchImage puts an image: in the device's
// temporary directory, which TeardownDevice removes.
func (dev *qemuDevice) scratchImagePath(imageName string) string {
	return filepath.Join(dev.tmpDir, "scratch-"+imageName+".raw")
}

// CreateScratchImage creates a sparse raw image in the device's temporary
// directory. QEMU runs on this host, so the path is directly usable in QMP
// commands.
func (p *QemuProvider) CreateScratchImage(ctx context.Context, name, imageName string,
	sizeBytes uint64) (string, error) {
	log := logger.FromContext(ctx)
	if err := ValidateScratchImageName(imageName); err != nil {
		return "", err
	}
	p.mutex.Lock()
	dev, ok := p.devices[name]
	p.mutex.Unlock()
	if !ok {
		return "", fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
	}

	path := dev.scratchImagePath(imageName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("scratch image %q of device %q already exists",
				imageName, name)
		}
		return "", fmt.Errorf("failed to create scratch image %s: %w", path, err)
	}
	if err := f.Truncate(int64(sizeBytes)); err != nil {
		closeErr := f.Close()
		removeErr := os.Remove(path)
		return "", fmt.Errorf("failed to size scratch image %s: %w", path, errors.Join(err, closeErr, removeErr))
	}
	if err := f.Close(); err != nil {
		removeErr := os.Remove(path)
		return "", fmt.Errorf("failed to close scratch image %s: %w", path, errors.Join(err, removeErr))
	}
	log.Infof("Created scratch image %s (%d bytes) for device %q", path, sizeBytes, name)
	return path, nil
}

// DeleteScratchImage removes an image created by CreateScratchImage.
func (p *QemuProvider) DeleteScratchImage(ctx context.Context, name, imageName string) error {
	log := logger.FromContext(ctx)
	if err := ValidateScratchImageName(imageName); err != nil {
		return err
	}
	p.mutex.Lock()
	dev, ok := p.devices[name]
	p.mutex.Unlock()
	if !ok {
		return fmt.Errorf("failed to lookup device %q: %w", name, ErrNotFound)
	}

	path := dev.scratchImagePath(imageName)
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("device %q has no scratch image %q", name, imageName)
		}
		return fmt.Errorf("failed to remove scratch image %s: %w", path, err)
	}
	log.Infof("Removed scratch image %s of device %q", path, name)
	return nil
}
