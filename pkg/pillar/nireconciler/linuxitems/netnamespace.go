// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"os/exec"
	"runtime"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

func namespacedCmd(netNs string, cmd string, args ...string) *exec.Cmd {
	if netNs == "" {
		return exec.Command(cmd, args...)
	}
	var newArgs []string
	newArgs = append(newArgs, "netns", "exec", netNs)
	newArgs = append(newArgs, cmd)
	newArgs = append(newArgs, args...)
	return exec.Command("ip", newArgs...)
}

func moveLinkToNamespace(link netlink.Link, netNs string) (err error) {
	nsHandle, err := netns.GetFromName(netNs)
	if err != nil {
		return err
	}
	return netlink.LinkSetNsFd(link, int(nsHandle))
}

func switchToNamespace(log *base.LogObject, netNs string) (revert func(), err error) {
	// Save the current network namespace.
	origNs, err := netns.Get()
	if err != nil {
		return func() {}, err
	}
	closeNs := func(ns netns.NsHandle) {
		if err := ns.Close(); err != nil {
			log.Warnf("closing NsHandle (%v) failed: %v", ns, err)
		}
	}
	// Get network namespace file descriptor.
	nsHandle, err := netns.GetFromName(netNs)
	if err != nil {
		closeNs(origNs)
		return func() {}, err
	}
	defer closeNs(nsHandle)

	// Lock the OS Thread so we don't accidentally switch namespaces later.
	runtime.LockOSThread()

	// Switch the namespace.
	if err := netns.Set(nsHandle); err != nil {
		runtime.UnlockOSThread()
		closeNs(origNs)
		return func() {}, err
	}

	return func() {
		if err := netns.Set(origNs); err != nil {
			log.Errorf("Failed to switch to original Linux network namespace: %v", err)
		}
		closeNs(origNs)
		runtime.UnlockOSThread()
	}, nil
}
