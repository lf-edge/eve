// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package linuxitems

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/containerd"
	"github.com/lf-edge/eve/pkg/pillar/dpcreconciler/genericitems"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	defaultVethMTU = 1500
	// containerdCallTimeout bounds a containerd lookup, so that a wedged
	// containerd cannot stall the reconciler.
	containerdCallTimeout = 10 * time.Second
	// containerWaitTimeout is how long Create waits for a container task.
	containerWaitTimeout = 10 * time.Minute
)

// containerPollPeriod is a variable for unit tests.
var containerPollPeriod = 2 * time.Second

// lookupContainerPID is a variable for unit tests.
var lookupContainerPID = containerPID

// errContainerNotRunning: the container task exists but is not running.
var errContainerNotRunning = errors.New("container task is not running")

// Veth : virtual Ethernet device pair.
type Veth struct {
	// VethName : logical name for the veth pair as a whole.
	VethName string
	Peer1    VethPeer
	Peer2    VethPeer
}

// VethPeer : one side of a Veth pair. Exactly one of AdapterIfName or
// ContainerName should be set.
type VethPeer struct {
	// IfName : name given to this side of the veth pair.
	IfName string
	// AdapterIfName : if non-empty, this peer is put under the Linux
	// bridge owned by the Adapter.
	AdapterIfName string
	// ContainerName : if non-empty, this peer is moved into the network
	// namespace of the named containerd system-service container.
	ContainerName string
	// IPAddresses : IP addresses to assign to this peer. Only meaningful
	// in the ContainerName mode.
	IPAddresses []*net.IPNet
	// MTU : Maximum transmission unit.
	MTU uint16
}

// Name returns the name of the veth pair item.
func (v Veth) Name() string {
	return v.VethName
}

// Label returns the label of the veth pair item.
func (v Veth) Label() string {
	return v.VethName + " (veth)"
}

// Type returns the typename of the veth pair item.
func (v Veth) Type() string {
	return VethTypename
}

// Equal is a comparison method for two equally-named Veth instances.
func (v Veth) Equal(other depgraph.Item) bool {
	v2 := other.(Veth)
	return v.Peer1.Equal(v2.Peer1) && v.Peer2.Equal(v2.Peer2)
}

// Equal compares two veth peers for equality.
func (v VethPeer) Equal(v2 VethPeer) bool {
	if v.IfName != v2.IfName ||
		v.AdapterIfName != v2.AdapterIfName ||
		v.ContainerName != v2.ContainerName ||
		v.MTU != v2.MTU {
		return false
	}
	return generics.EqualSetsFn(v.IPAddresses, v2.IPAddresses, netutils.EqualIPNets)
}

// External returns false.
func (v Veth) External() bool {
	return false
}

// String describes veth.
func (v Veth) String() string {
	return fmt.Sprintf("veth: %#+v", v)
}

// Dependencies lists the Adapter (bridge) side, if any, as a veth dependency.
func (v Veth) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, v.Peer1.Dependencies()...)
	deps = append(deps, v.Peer2.Dependencies()...)
	return deps
}

// Dependencies of a single veth side.
func (v VethPeer) Dependencies() (deps []depgraph.Dependency) {
	if v.AdapterIfName != "" {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: genericitems.AdapterTypename,
				ItemName: v.AdapterIfName,
			},
			Description: "Adapter (and its bridge) must exist",
		})
	}
	return deps
}

// VethConfigurator implements Configurator interface for veth.
type VethConfigurator struct {
	Log *base.LogObject
}

// Create adds new veth. With a container peer, it waits in the background
// for the container task to run (the container may start after pillar).
func (c *VethConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	vethCfg := item.(Veth)
	if vethCfg.Peer1.ContainerName == "" && vethCfg.Peer2.ContainerName == "" {
		return c.create(ctx, vethCfg)
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		done(c.create(ctx, vethCfg))
	}()
	return nil
}

func (c *VethConfigurator) create(ctx context.Context, vethCfg Veth) error {
	for _, peer := range []VethPeer{vethCfg.Peer1, vethCfg.Peer2} {
		if peer.ContainerName == "" {
			continue
		}
		if err := c.waitForContainer(ctx, peer.ContainerName); err != nil {
			c.Log.Error(err)
			return err
		}
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = vethCfg.Peer1.IfName
	link := &netlink.Veth{
		LinkAttrs: attrs,
		PeerName:  vethCfg.Peer2.IfName,
	}
	if err := netlink.LinkAdd(link); err != nil {
		err = fmt.Errorf("failed to add veth %s/%s: %v",
			vethCfg.Peer1.IfName, vethCfg.Peer2.IfName, err)
		c.Log.Error(err)
		return err
	}
	if err := c.configurePeer(ctx, vethCfg.Peer1); err != nil {
		// Best-effort cleanup so a retry starts from a clean state.
		_ = netlink.LinkDel(link)
		c.Log.Error(err)
		return err
	}
	if err := c.configurePeer(ctx, vethCfg.Peer2); err != nil {
		_ = netlink.LinkDel(link)
		c.Log.Error(err)
		return err
	}
	return nil
}

// waitForContainer blocks until the container task runs, ctx is canceled
// or containerWaitTimeout expires.
func (c *VethConfigurator) waitForContainer(ctx context.Context, name string) error {
	ctx, cancel := context.WithTimeout(ctx, containerWaitTimeout)
	defer cancel()
	ticker := time.NewTicker(containerPollPeriod)
	defer ticker.Stop()
	for {
		_, err := lookupContainerPID(ctx, name)
		if err == nil {
			return nil
		}
		c.Log.Functionf("waiting for container %s to run: %v", name, err)
		select {
		case <-ctx.Done():
			return fmt.Errorf("container %s did not start in time: %w (last error: %v)",
				name, ctx.Err(), err)
		case <-ticker.C:
		}
	}
}

func (c *VethConfigurator) configurePeer(ctx context.Context, peer VethPeer) error {
	link, err := netlink.LinkByName(peer.IfName)
	if err != nil {
		return fmt.Errorf("failed to get link for veth peer %s: %w", peer.IfName, err)
	}

	if peer.ContainerName != "" {
		pid, err := lookupContainerPID(ctx, peer.ContainerName)
		if err != nil {
			return fmt.Errorf("failed to find running task of container %s "+
				"(for veth peer %s): %w", peer.ContainerName, peer.IfName, err)
		}
		if err := netlink.LinkSetNsPid(link, pid); err != nil {
			return fmt.Errorf("failed to move veth peer %s into container %s "+
				"(pid %d) netns: %w", peer.IfName, peer.ContainerName, pid, err)
		}
		revertNs, err := switchToContainerNetns(c.Log, pid)
		if err != nil {
			return fmt.Errorf("failed to switch to container %s (pid %d) netns: %w",
				peer.ContainerName, pid, err)
		}
		defer revertNs()
		link, err = netlink.LinkByName(peer.IfName)
		if err != nil {
			return fmt.Errorf("failed to get link for veth peer %s inside "+
				"container %s netns: %w", peer.IfName, peer.ContainerName, err)
		}
	}

	if peer.AdapterIfName != "" {
		bridge, err := netlink.LinkByName(peer.AdapterIfName)
		if err != nil {
			return fmt.Errorf("failed to get bridge %s (for enslavement of "+
				"veth peer %s): %w", peer.AdapterIfName, peer.IfName, err)
		}
		mtu := bridge.Attrs().MTU
		if err := netlink.LinkSetMaster(link, bridge); err != nil {
			return fmt.Errorf("failed to put veth peer %s under bridge %s: %w",
				peer.IfName, peer.AdapterIfName, err)
		}
		// MTU is sometimes lost when a new interface is put under the bridge.
		if err := netlink.LinkSetMTU(bridge, mtu); err != nil {
			return fmt.Errorf("failed to restore bridge %s MTU %d (after "+
				"enslaving veth peer %s): %w", peer.AdapterIfName, mtu, peer.IfName, err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set veth peer %s UP: %v", peer.IfName, err)
	}

	for _, ipNet := range peer.IPAddresses {
		addr := &netlink.Addr{IPNet: ipNet}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return fmt.Errorf("failed to add addr %v to veth peer %s: %v",
				ipNet, peer.IfName, err)
		}
	}

	mtu := peer.MTU
	if mtu == 0 {
		mtu = defaultVethMTU
	}
	if err := netlink.LinkSetMTU(link, int(mtu)); err != nil {
		return fmt.Errorf("netlink.LinkSetMTU(%s, %d) failed: %v",
			link.Attrs().Name, mtu, err)
	}
	return nil
}

// Modify is not implemented (veth is recreated on change).
func (c *VethConfigurator) Modify(_ context.Context, _, _ depgraph.Item) error {
	return errors.New("not implemented")
}

// Delete removes veth. Removing one side is enough - the kernel removes
// the peer automatically. No-op if the pair is already gone (e.g. the
// container exited and took its netns away).
func (c *VethConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	vethCfg := item.(Veth)
	peer := vethCfg.Peer1
	if peer.ContainerName != "" {
		pid, err := lookupContainerPID(ctx, peer.ContainerName)
		if errors.Is(err, errContainerNotRunning) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to find running task of container %s "+
				"(for veth peer %s removal): %w", peer.ContainerName, peer.IfName, err)
		}
		revertNs, err := switchToContainerNetns(c.Log, pid)
		if err != nil {
			return fmt.Errorf("failed to switch to container %s (pid %d) netns: %w",
				peer.ContainerName, pid, err)
		}
		defer revertNs()
	}
	link, err := netlink.LinkByName(peer.IfName)
	if err != nil {
		var notFound netlink.LinkNotFoundError
		if errors.As(err, &notFound) {
			return nil
		}
		return fmt.Errorf("failed to select veth peer %s for removal: %w",
			peer.IfName, err)
	}
	if err := netlink.LinkDel(link); err != nil {
		return fmt.Errorf("failed to delete veth peer %s: %w", peer.IfName, err)
	}
	return nil
}

// NeedsRecreate returns true. Modify is not implemented.
func (c *VethConfigurator) NeedsRecreate(_, _ depgraph.Item) bool {
	return true
}

// containerPID returns the PID of the named containerd system-service
// container's main task. Returns an error if the container/task doesn't
// exist yet or isn't running (errContainerNotRunning in the latter case).
func containerPID(ctx context.Context, containerName string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, containerdCallTimeout)
	defer cancel()
	client, err := containerd.NewContainerdClient(false)
	if err != nil {
		return 0, fmt.Errorf("failed to create containerd client: %w", err)
	}
	defer client.CloseClient()
	ctrdCtx, done := client.CtrNewSystemServicesCtx()
	defer done()
	// The containerd context derives from Background; link it to ours.
	stop := context.AfterFunc(ctx, done)
	defer stop()
	pid, _, status, err := client.CtrContainerInfo(ctrdCtx, containerName)
	if err != nil {
		return 0, err
	}
	if status != "running" {
		return 0, fmt.Errorf("container %s task (status=%s): %w",
			containerName, status, errContainerNotRunning)
	}
	return pid, nil
}

// switchToContainerNetns switches the calling goroutine's OS thread into
// the network namespace of the given PID, returning a function to switch
// back and unlock the thread.
func switchToContainerNetns(log *base.LogObject, pid int) (revert func(), err error) {
	origNs, err := netns.Get()
	if err != nil {
		return func() {}, err
	}
	closeNs := func(ns netns.NsHandle) {
		if err := ns.Close(); err != nil {
			log.Warnf("closing NsHandle (%v) failed: %v", ns, err)
		}
	}
	nsHandle, err := netns.GetFromPid(pid)
	if err != nil {
		closeNs(origNs)
		return func() {}, err
	}
	defer closeNs(nsHandle)

	runtime.LockOSThread()
	if err := netns.Set(nsHandle); err != nil {
		runtime.UnlockOSThread()
		closeNs(origNs)
		return func() {}, err
	}

	return func() {
		if err := netns.Set(origNs); err != nil {
			log.Errorf("Failed to switch back to original netns: %v", err)
		}
		closeNs(origNs)
		runtime.UnlockOSThread()
	}, nil
}
