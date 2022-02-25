package domainmgr

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/vishvananda/netlink"
)

const MaxVfCount = 255

func createVF(device string, vfCount uint8) error {
	name := filepath.Join(types.NicLinuxPath, device, types.NumvfsDevicePath)
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	_, err = f.Write([]byte(strconv.Itoa(int(vfCount))))
	if err1 := f.Sync(); err1 != nil && err == nil {
		err = err1
	}
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	return err
}

func getVfByTimeout(timeout time.Duration, device string) (*types.VFList, error) {
	toCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := asyncGetVF(toCtx, device)
	for {
		select {
		case ans := <-c:
			return ans, nil
		case <-toCtx.Done():
			return nil, fmt.Errorf("getVfByTimeout reached timeout %v", timeout)
		}
	}
}

func asyncGetVF(ctx context.Context, device string) chan *types.VFList {
	ch := make(chan *types.VFList)
	go func() {
		select {
		default:
			time.Sleep(1 * time.Second)
			vfs, _ := types.GetVf(device)
			if len(vfs.Data) != 0 {
				ch <- vfs
				break
			}
		case <-ctx.Done():
			return
		}
	}()
	return ch
}

func setupVfHardwareAddr(iface string, mac string, index uint8) error {
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %v", iface, err)
	}
	macAddr, err := net.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("Failed to parse mac address %s: %v", mac, err)
	}
	if err = netlink.LinkSetVfHardwareAddr(pf, int(index), macAddr); err != nil {
		return fmt.Errorf("Failed to set vf %d mac address: %v", index, err)
	}

	return nil
}

func setupVfVlan(iface string, index uint8, vlanId uint16) error {
	if vlanId == 0 {
		// Either vlan is not initialized or not used
		return nil
	}
	pf, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("Failed to find physical function %s: %v", iface, err)
	}

	if err = netlink.LinkSetVfVlan(pf, int(index), int(vlanId)); err != nil {
		return fmt.Errorf("Failed to set vf %d vlan: %v", index, err)
	}
	return nil
}
