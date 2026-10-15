// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/evetest/sdn/vm/pkg/maclookup"
	log "github.com/sirupsen/logrus"
)

const (
	dhcpcdBinary       = "/sbin/dhcpcd"
	dhcpcdStartTimeout = 5 * time.Second
	dhcpcdStopTimeout  = 30 * time.Second
)

// DhcpClient : DHCP client (this one: https://wiki.archlinux.org/title/dhcpcd).
// Can be only used with physical network interface (not with virtual interfaces like VETH).
type DhcpClient struct {
	// PhysIf : physical interface to associate the client with.
	PhysIf PhysIf
	// LogFile : where to put dhcpcd logs.
	LogFile string
}

// Name returns the name of the DHCP client item.
func (c DhcpClient) Name() string {
	return c.PhysIf.MAC.String()
}

// Label returns the label of the DHCP client item.
func (c DhcpClient) Label() string {
	return "DHCP client for " + c.PhysIf.LogicalLabel
}

// Type returns the typename of the DHCP client item.
func (c DhcpClient) Type() string {
	return DhcpClientTypename
}

// Equal is a comparison method for two equally-named DhcpClient instances.
func (c DhcpClient) Equal(other depgraph.Item) bool {
	c2 := other.(DhcpClient)
	return c.PhysIf.Equal(c2.PhysIf) &&
		c.LogFile == c2.LogFile
}

// External returns false.
func (c DhcpClient) External() bool {
	return false
}

// String describes the DHCP client config.
func (c DhcpClient) String() string {
	return fmt.Sprintf("DHCP Client: %#+v", c)
}

// Dependencies lists the IfHandle as the only dependency of the DHCP client.
func (c DhcpClient) Dependencies() (deps []depgraph.Dependency) {
	return []depgraph.Dependency{
		{
			RequiredItem: depgraph.ItemRef{
				ItemType: IfHandleTypename,
				ItemName: c.PhysIf.MAC.String(),
			},
			MustSatisfy: func(item depgraph.Item) bool {
				ifHandle := item.(IfHandle)
				return ifHandle.Usage == IfUsageL3
			},
			Description: "Physical network interface must exist and be used in the L3 mode",
		},
	}
}

// DhcpClientConfigurator implements Configurator interface for DhcpClient.
type DhcpClientConfigurator struct {
	MacLookup *maclookup.MacLookup
}

// Create starts dhcpcd.
func (c *DhcpClientConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(DhcpClient)
	mac := config.PhysIf.MAC
	netIf, found := c.MacLookup.GetInterfaceByMAC(mac, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", mac)
		log.Error(err)
		return err
	}
	ifName := netIf.IfName
	done := reconciler.ContinueInBackground(ctx)

	go func() {
		if isDhcpcdRunning(ifName) {
			err := fmt.Errorf("dhcpcd for interface %s is already running", ifName)
			log.Error(err)
			done(err)
			return
		}
		// Start DHCP client.
		var args []string
		if config.LogFile != "" {
			args = append(args, "-j", config.LogFile)
		}
		args = append(args, "-t", "0") // wait for release forever
		args = append(args, ifName)
		err := startProcess(MainNsName, dhcpcdBinary, args, dhcpcdPidFile(ifName), "",
			dhcpcdStartTimeout, false, true)
		if err != nil {
			done(err)
			return
		}
		log.Debugf("dhcpcd for interface %s is running", ifName)
		done(nil)
	}()
	return nil
}

// Modify is not implemented.
func (c *DhcpClientConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops dhcpcd.
func (c *DhcpClientConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(DhcpClient)
	mac := config.PhysIf.MAC
	netIf, found := c.MacLookup.GetInterfaceByMAC(mac, false)
	if !found {
		err := fmt.Errorf("failed to get physical interface with MAC %v", mac)
		log.Error(err)
		return err
	}
	ifName := netIf.IfName
	done := reconciler.ContinueInBackground(ctx)

	go func() {
		startTime := time.Now()
		// Run release, wait for a bit, then exit and give up.
		failed := false
		for {
			// Release DHCP lease and un-configure the interface.
			// It waits up to 10 seconds.
			// https://github.com/NetworkConfiguration/dhcpcd/blob/dhcpcd-8.1.6/src/dhcpcd.c#L1950-L1957
			_, err := exec.Command(dhcpcdBinary, "--release", ifName).CombinedOutput()
			if err != nil {
				log.Errorf("dhcpcd release failed for interface %s: %v, elapsed time %v",
					ifName, err, time.Since(startTime))
			}
			if !isDhcpcdRunning(ifName) {
				break
			}
			if time.Since(startTime) > dhcpcdStopTimeout {
				log.Errorf("dhcpcd for interface %s is still running, will exit it, elapsed time %v",
					ifName, time.Since(startTime))
				failed = true
				break
			}
			log.Warnf("dhcpcd for interface %s is still running, elapsed time %v",
				ifName, time.Since(startTime))
			time.Sleep(1 * time.Second)
		}
		if !failed {
			log.Debugf("dhcpcd for interface %s is gone, elapsed time %v",
				ifName, time.Since(startTime))
			done(nil)
			return
		}
		// Exit dhcpcd running on the interface.
		// It waits up to 10 seconds.
		// https://github.com/NetworkConfiguration/dhcpcd/blob/dhcpcd-8.1.6/src/dhcpcd.c#L1950-L1957
		_, err := exec.Command(dhcpcdBinary, "--exit", ifName).CombinedOutput()
		if err != nil {
			err = fmt.Errorf("dhcpcd exit failed for interface %s: %v, elapsed time %v",
				ifName, err, time.Since(startTime))
			log.Error(err)
			done(err)
			return
		}
		if !isDhcpcdRunning(ifName) {
			log.Infof("dhcpcd for interface %s is gone after exit, elapsed time %v",
				ifName, time.Since(startTime))
			done(nil)
			return
		}
		err = fmt.Errorf("exiting dhcpcd for interface %s is still running, elapsed time %v",
			ifName, time.Since(startTime))
		log.Error(err)
		done(err)
	}()
	return nil
}

func dhcpcdPidFile(ifName string) string {
	return fmt.Sprintf("/run/dhcpcd/%s.pid", ifName)
}

func isDhcpcdRunning(ifName string) bool {
	pidFile := dhcpcdPidFile(ifName)
	return isProcessRunning(pidFile)
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *DhcpClientConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}
