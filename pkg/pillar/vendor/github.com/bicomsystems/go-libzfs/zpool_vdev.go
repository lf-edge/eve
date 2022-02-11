package zfs

// #include <stdlib.h>
// #include <libzfs.h>
// #include "common.h"
// #include "zpool.h"
// #include "zfs.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// Online try to set dev online
// expand - expand storage
func (pool *Pool) Online(expand bool, devs ...string) (err error) {
	cflags := C.int(0)
	if expand {
		cflags = C.ZFS_ONLINE_EXPAND
	}
	for _, dev := range devs {
		csdev := C.CString(dev)
		var newstate VDevState
		if newstate = VDevState(C.set_zpool_vdev_online(pool.list, csdev, cflags)); newstate != VDevStateUnknown {
			if newstate != VDevStateHealthy {
				err = fmt.Errorf(
					"Device '%s' onlined, but remains in faulted state",
					dev)
			}
		} else {
			err = LastError()
		}
		C.free(unsafe.Pointer(csdev))
	}
	return
}

// Offline Take the device/s in offline state
func (pool *Pool) Offline(force bool, devs ...string) (err error) {
	return pool.offline(false, force, devs...)
}

// OfflineTemp Take the device/s in offline state temporary,
// upon reboot, the specified physical device reverts to its previous state.
// force - Force the device into a faulted state.
func (pool *Pool) OfflineTemp(force bool, devs ...string) (err error) {
	return pool.offline(true, force, devs...)
}

// temp  - Upon reboot, the specified physical device reverts to its previous state.
// force - Force the device into a faulted state.
func (pool *Pool) offline(temp, force bool, devs ...string) (err error) {
	for _, dev := range devs {
		csdev := C.CString(dev)
		var newstate VDevState
		if newstate = VDevState(C.set_zpool_vdev_offline(pool.list, csdev, booleanT(temp), booleanT(force))); newstate != VDevStateUnknown {
			if newstate != VDevStateHealthy {
				err = fmt.Errorf(
					"Device '%s' offlined, but remains in faulted state",
					dev)
			}
		} else {
			err = LastError()
		}
		C.free(unsafe.Pointer(csdev))
	}
	return
}

// Clear - Clear all errors associated with a pool or a particular device.
func (pool *Pool) Clear(device string) (err error) {
	csdev := C.CString(device)
	if len(device) == 0 {
		csdev = nil
	}
	if sc := C.do_zpool_clear(pool.list, csdev, C.ZPOOL_NO_REWIND); sc != 0 {
		err = fmt.Errorf("Pool clear failed")
	}
	C.free(unsafe.Pointer(csdev))
	return
}

// Attach test
// func (pool *Pool) attach(props PoolProperties, devs ...string) (err error) {
// 	cprops := toCPoolProperties(props)
// 	if cprops != nil {
// 		defer C.nvlist_free(cprops)
// 	} else {
// 		return fmt.Errorf("Out of memory [Pool Attach properties]")
// 	}
// 	cdevs := C.alloc_cstrings(C.int(len(devs)))
// 	if cdevs != nil {
// 		defer C.free(unsafe.Pointer(cdevs))
// 	} else {
// 		return fmt.Errorf("Out of memory [Pool Attach args]")
// 	}
// 	for i, dp := range devs {
// 		tmp := C.CString(dp)
// 		if tmp != nil {
// 			defer C.free(unsafe.Pointer(tmp))
// 		} else {
// 			return fmt.Errorf("Out of memory [Pool Attach dev]")
// 		}
// 		C.strings_setat(cdevs, C.int(i), tmp)
// 	}
// 	// vroot := C.make_root_vdev(pool.list.zph, cprops, 0, 0, 0, 0, len(devs), cdevs)
// 	var nvroot *C.struct_nvlist
// 	if r := C.nvlist_alloc(&nvroot, C.NV_UNIQUE_NAME, 0); r != 0 {
// 		err = errors.New("Failed to allocate root vdev")
// 		return
// 	}
// 	csTypeRoot := C.CString(string(VDevTypeRoot))
// 	r := C.nvlist_add_string(nvroot, C.sZPOOL_CONFIG_TYPE,
// 		csTypeRoot)
// 	C.free(unsafe.Pointer(csTypeRoot))
// 	if r != 0 {
// 		err = errors.New("Failed to allocate root vdev")
// 		return
// 	}
// 	defer C.nvlist_free(nvroot)

// 	// Now we need to build specs (vdev hierarchy)
// 	if err = buildVDevTree(nvroot, VDevTypeRoot, vdev.Devices, vdev.Spares, vdev.L2Cache, props); err != nil {
// 		return
// 	}

// 	return
// }

// func (pool *Pool) AttachForce(devs ...string) (err error) {
// 	return
// }

// func (pool *Pool) Detach(devs ...string) (err error) {
// 	return
// }

// func (pool *Pool) DetachForce(devs ...string) (err error) {
// 	return
// }

// func (pool *Pool) Replace(devs ...string) (err error) {
// 	return
// }
