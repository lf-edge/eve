package zfs

// #cgo CFLAGS: -D__USE_LARGEFILE64=1
// #include <stdlib.h>
// #include <libzfs.h>
// #include "common.h"
// #include "zpool.h"
// #include "zfs.h"
import "C"

import (
	"errors"
	"fmt"
	"strconv"
	"time"
	"unsafe"
)

const (
	msgPoolIsNil = "Pool handle not initialized or its closed"
)

// Enable or disable pool feature with this constants
const (
	FENABLED  = "enabled"
	FDISABLED = "disabled"
)

// PoolProperties type is map of pool properties name -> value
type PoolProperties map[Prop]string

/*
 * ZIO types.  Needed to interpret vdev statistics below.
 */
const (
	ZIOTypeNull = iota
	ZIOTypeRead
	ZIOTypeWrite
	ZIOTypeFree
	ZIOTypeClaim
	ZIOTypeIOCtl
	ZIOTypes
)

// Scan states
const (
	DSSNone      = iota // No scan
	DSSScanning         // Scanning
	DSSFinished         // Scan finished
	DSSCanceled         // Scan canceled
	DSSNumStates        // Total number of scan states
)

// Scan functions
const (
	PoolScanNone     = iota // No scan function
	PoolScanScrub           // Pools is checked against errors
	PoolScanResilver        // Pool is resilvering
	PoolScanFuncs           // Number of scan functions
)

// PoolInitializeAction type representing pool initialize action
type PoolInitializeAction int

// Initialize actions
const (
	PoolInitializeStart   PoolInitializeAction = iota // start initialization
	PoolInitializeCancel                              // cancel initialization
	PoolInitializeSuspend                             // suspend initialization
)

// VDevStat - Vdev statistics.  Note: all fields should be 64-bit because this
// is passed between kernel and userland as an nvlist uint64 array.
type VDevStat struct {
	Timestamp      time.Duration    /* time since vdev load	(nanoseconds)*/
	State          VDevState        /* vdev state		*/
	Aux            VDevAux          /* see vdev_aux_t	*/
	Alloc          uint64           /* space allocated	*/
	Space          uint64           /* total capacity	*/
	DSpace         uint64           /* deflated capacity	*/
	RSize          uint64           /* replaceable dev size */
	ESize          uint64           /* expandable dev size */
	Ops            [ZIOTypes]uint64 /* operation count	*/
	Bytes          [ZIOTypes]uint64 /* bytes read/written	*/
	ReadErrors     uint64           /* read errors		*/
	WriteErrors    uint64           /* write errors		*/
	ChecksumErrors uint64           /* checksum errors	*/
	SelfHealed     uint64           /* self-healed bytes	*/
	ScanRemoving   uint64           /* removing?	*/
	ScanProcessed  uint64           /* scan processed bytes	*/
	Fragmentation  uint64           /* device fragmentation */
}

// PoolScanStat - Pool scan statistics
type PoolScanStat struct {
	// Values stored on disk
	Func      uint64 // Current scan function e.g. none, scrub ...
	State     uint64 // Current scan state e.g. scanning, finished ...
	StartTime uint64 // Scan start time
	EndTime   uint64 // Scan end time
	ToExamine uint64 // Total bytes to scan
	Examined  uint64 // Total bytes scaned
	Processed uint64 // Total bytes processed
	Errors    uint64 // Scan errors
	// Values not stored on disk
	PassExam  uint64 // Examined bytes per scan pass
	PassStart uint64 // Start time of scan pass
}

// VDevTree ZFS virtual device tree
type VDevTree struct {
	Type     VDevType
	Devices  []VDevTree // groups other devices (e.g. mirror)
	Spares   []VDevTree
	L2Cache  []VDevTree
	Logs     *VDevTree
	GUID     uint64
	Parity   uint
	Path     string
	Name     string
	Stat     VDevStat
	ScanStat PoolScanStat
}

// ExportedPool is type representing ZFS pool available for import
type ExportedPool struct {
	VDevs   VDevTree
	Name    string
	Comment string
	GUID    uint64
	State   PoolState
	Status  PoolStatus
}

// Pool object represents handler to single ZFS pool
//
/* Pool.Properties map[string]Property
 */
// Map of all ZFS pool properties, changing any of this will not affect ZFS
// pool, for that use SetProperty( name, value string) method of the pool
// object. This map is initial loaded when ever you open or create pool to
// give easy access to listing all available properties. It can be refreshed
// with up to date values with call to (*Pool) ReloadProperties
type Pool struct {
	list       C.zpool_list_ptr
	Properties []Property
	Features   map[string]string
}

// PoolOpen open ZFS pool handler by name.
// Returns Pool object, requires Pool.Close() to be called explicitly
// for memory cleanup after object is not needed anymore.
func PoolOpen(name string) (pool Pool, err error) {
	csName := C.CString(name)
	defer C.free(unsafe.Pointer(csName))
	pool.list = C.zpool_list_open(csName)

	if pool.list != nil {
		err = pool.ReloadProperties()
		return
	}
	err = LastError()
	return
}

func poolGetConfig(name string, nv C.nvlist_ptr) (vdevs VDevTree, err error) {
	var dtype C.char_ptr
	var vs C.vdev_stat_ptr
	var ps C.pool_scan_stat_ptr
	var children C.vdev_children_ptr
	if dtype = C.get_vdev_type(nv); dtype == nil {
		err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_TYPE)
		return
	}
	vdevs.Name = name
	vdevs.Type = VDevType(C.GoString(dtype))
	if vdevs.Type == VDevTypeMissing || vdevs.Type == VDevTypeHole {
		return
	}

	vdevs.GUID = uint64(C.get_vdev_guid(nv))

	// Fetch vdev state
	if vs = C.get_vdev_stats(nv); vs == nil {
		err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_VDEV_STATS)
		return
	}
	vdevs.Stat.Timestamp = time.Duration(vs.vs_timestamp)
	vdevs.Stat.State = VDevState(vs.vs_state)
	vdevs.Stat.Aux = VDevAux(vs.vs_aux)
	vdevs.Stat.Alloc = uint64(vs.vs_alloc)
	vdevs.Stat.Space = uint64(vs.vs_space)
	vdevs.Stat.DSpace = uint64(vs.vs_dspace)
	vdevs.Stat.RSize = uint64(vs.vs_rsize)
	vdevs.Stat.ESize = uint64(vs.vs_esize)
	for z := 0; z < ZIOTypes; z++ {
		vdevs.Stat.Ops[z] = uint64(vs.vs_ops[z])
		vdevs.Stat.Bytes[z] = uint64(vs.vs_bytes[z])
	}
	vdevs.Stat.ReadErrors = uint64(vs.vs_read_errors)
	vdevs.Stat.WriteErrors = uint64(vs.vs_write_errors)
	vdevs.Stat.ChecksumErrors = uint64(vs.vs_checksum_errors)
	vdevs.Stat.SelfHealed = uint64(vs.vs_self_healed)
	vdevs.Stat.ScanRemoving = uint64(vs.vs_scan_removing)
	vdevs.Stat.ScanProcessed = uint64(vs.vs_scan_processed)
	vdevs.Stat.Fragmentation = uint64(vs.vs_fragmentation)

	// Fetch vdev scan stats
	if ps = C.get_vdev_scan_stats(nv); ps != nil {
		vdevs.ScanStat.Func = uint64(ps.pss_func)
		vdevs.ScanStat.State = uint64(ps.pss_state)
		vdevs.ScanStat.StartTime = uint64(ps.pss_start_time)
		vdevs.ScanStat.EndTime = uint64(ps.pss_end_time)
		vdevs.ScanStat.ToExamine = uint64(ps.pss_to_examine)
		vdevs.ScanStat.Examined = uint64(ps.pss_examined)
		vdevs.ScanStat.Processed = uint64(ps.pss_processed)
		vdevs.ScanStat.Errors = uint64(ps.pss_errors)
		vdevs.ScanStat.PassExam = uint64(ps.pss_pass_exam)
		vdevs.ScanStat.PassStart = uint64(ps.pss_pass_start)
	}

	// Fetch the children
	children = C.get_vdev_children(nv)
	if children != nil {
		// this object that reference childrens and count should be deallocated from memory
		defer C.free(unsafe.Pointer(children))
		vdevs.Devices = make([]VDevTree, 0, children.count)
	}
	path := C.get_vdev_path(nv)
	if path != nil {
		vdevs.Path = C.GoString(path)
	}
	for c := C.uint_t(0); children != nil && c < children.count; c++ {
		var islog = C.uint64_t(C.B_FALSE)

		islog = C.get_vdev_is_log(C.nvlist_array_at(children.first, c))

		vname := C.zpool_vdev_name(C.libzfsHandle, nil, C.nvlist_array_at(children.first, c),
			C.B_TRUE)
		var vdev VDevTree
		vdev, err = poolGetConfig(C.GoString(vname),
			C.nvlist_array_at(children.first, c))
		C.free(unsafe.Pointer(vname))
		if err != nil {
			return
		}
		if islog != C.B_FALSE {
			vdevs.Logs = &vdev
		} else {
			vdevs.Devices = append(vdevs.Devices, vdev)
		}
	}
	return
}

func poolGetSpares(name string, nv C.nvlist_ptr) (vdevs []VDevTree, err error) {
	// Fetch the spares
	var spares C.vdev_children_ptr
	spares = C.get_vdev_spares(nv)
	if spares != nil {
		// this object that reference spares and count should be deallocated from memory
		defer C.free(unsafe.Pointer(spares))
		vdevs = make([]VDevTree, 0, spares.count)
	}
	for c := C.uint_t(0); spares != nil && c < spares.count; c++ {
		vname := C.zpool_vdev_name(C.libzfsHandle, nil, C.nvlist_array_at(spares.first, c),
			C.B_TRUE)
		var vdev VDevTree
		vdev, err = poolGetConfig(C.GoString(vname),
			C.nvlist_array_at(spares.first, c))
		C.free(unsafe.Pointer(vname))
		if err != nil {
			return
		}
		vdevs = append(vdevs, vdev)
	}
	return
}

func poolGetL2Cache(name string, nv C.nvlist_ptr) (vdevs []VDevTree, err error) {
	// Fetch the spares
	var l2cache C.vdev_children_ptr
	l2cache = C.get_vdev_l2cache(nv)
	if l2cache != nil {
		// this object that reference l2cache and count should be deallocated from memory
		defer C.free(unsafe.Pointer(l2cache))
		vdevs = make([]VDevTree, 0, l2cache.count)
	}
	for c := C.uint_t(0); l2cache != nil && c < l2cache.count; c++ {
		vname := C.zpool_vdev_name(C.libzfsHandle, nil, C.nvlist_array_at(l2cache.first, c),
			C.B_TRUE)
		var vdev VDevTree
		vdev, err = poolGetConfig(C.GoString(vname),
			C.nvlist_array_at(l2cache.first, c))
		C.free(unsafe.Pointer(vname))
		if err != nil {
			return
		}
		vdevs = append(vdevs, vdev)
	}
	return
}

// PoolImportSearch - Search pools available to import but not imported.
// Returns array of found pools.
func PoolImportSearch(searchpaths []string) (epools []ExportedPool, err error) {
	var config, nvroot C.nvlist_ptr
	var cname, msgid, comment C.char_ptr
	var reason C.zpool_status_t
	var errata C.zpool_errata_t
	config = nil
	var elem C.nvpair_ptr
	numofp := len(searchpaths)
	cpaths := C.alloc_cstrings(C.int(numofp))
	defer C.free(unsafe.Pointer(cpaths))
	for i, path := range searchpaths {
		csPath := C.CString(path)
		defer C.free(unsafe.Pointer(csPath))
		C.strings_setat(cpaths, C.int(i), csPath)
	}

	pools := C.go_zpool_search_import(C.libzfsHandle, C.int(numofp), cpaths, C.B_FALSE)
	defer C.nvlist_free(pools)
	elem = C.nvlist_next_nvpair(pools, elem)
	epools = make([]ExportedPool, 0, 1)
	for ; elem != nil; elem = C.nvlist_next_nvpair(pools, elem) {
		ep := ExportedPool{}
		if C.nvpair_value_nvlist(elem, (**C.struct_nvlist)(&config)) != 0 {
			err = LastError()
			return
		}

		ep.State = PoolState(C.get_zpool_state(config))
		if ep.State == PoolStateDestroyed {
			continue // skip destroyed pools
		}

		if cname = C.get_zpool_name(config); cname == nil {
			err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_POOL_NAME)
			return
		}
		ep.Name = C.GoString(cname)

		ep.GUID = uint64(C.get_zpool_guid(config))

		reason = C.zpool_import_status(config, (**C.char)(&msgid), &errata)
		ep.Status = PoolStatus(reason)

		if comment = C.get_zpool_comment(config); comment != nil {
			ep.Comment = C.GoString(comment)
		}

		if nvroot = C.get_zpool_vdev_tree(config); nvroot == nil {
			err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_VDEV_TREE)
			return
		}
		ep.VDevs, err = poolGetConfig(ep.Name, nvroot)
		epools = append(epools, ep)
	}
	return
}

func poolSearchImport(q string, searchpaths []string, guid bool) (name string,
	err error) {
	var config C.nvlist_ptr
	var cname C.char_ptr
	config = nil
	errPoolList := errors.New("Failed to list pools")
	var elem *C.nvpair_t
	numofp := len(searchpaths)
	cpaths := C.alloc_cstrings(C.int(numofp))
	defer C.free(unsafe.Pointer(cpaths))
	for i, path := range searchpaths {
		csPath := C.CString(path)
		defer C.free(unsafe.Pointer(csPath))
		C.strings_setat(cpaths, C.int(i), csPath)
	}

	pools := C.go_zpool_search_import(C.libzfsHandle, C.int(numofp), cpaths, C.B_FALSE)
	defer C.nvlist_free(pools)

	elem = C.nvlist_next_nvpair(pools, elem)
	for ; elem != nil; elem = C.nvlist_next_nvpair(pools, elem) {
		var cq *C.char
		var tconfig *C.nvlist_t
		retcode := C.nvpair_value_nvlist(elem, (**C.struct_nvlist)(&tconfig))
		if retcode != 0 {
			err = errPoolList
			return
		}
		if PoolState(C.get_zpool_state(tconfig)) == PoolStateDestroyed {
			continue // skip destroyed pools
		}
		if guid {
			sguid := fmt.Sprint(C.get_zpool_guid(tconfig))
			if q == sguid {
				config = tconfig
				break
			}
		} else {
			if cq = C.get_zpool_name(tconfig); cq == nil {
				err = errPoolList
				return
			}
			cname = cq
			name = C.GoString(cq)
			if q == name {
				config = tconfig
				break
			}
		}
	}
	if config == nil {
		err = fmt.Errorf("No pool found %s", q)
		return
	}
	if guid {
		// We need to get name so we can open pool by name
		if cname = C.get_zpool_name(config); cname == nil {
			err = errPoolList
			return
		}
		name = C.GoString(cname)
	}
	if retcode := C.zpool_import_props(C.libzfsHandle, config, cname,
		nil, C.ZFS_IMPORT_NORMAL|C.ZFS_IMPORT_ANY_HOST); retcode != 0 {
		err = fmt.Errorf("Import pool properties failed: %s", LastError().Error())
		return
	}
	return
}

// PoolImport given a list of directories to search, find and import pool with matching
// name stored on disk.
func PoolImport(name string, searchpaths []string) (pool Pool, err error) {
	_, err = poolSearchImport(name, searchpaths, false)
	if err != nil {
		return
	}
	pool, err = PoolOpen(name)
	return
}

// PoolImportByGUID given a list of directories to search, find and import pool
// with matching GUID stored on disk.
func PoolImportByGUID(guid string, searchpaths []string) (pool Pool, err error) {
	var name string
	name, err = poolSearchImport(guid, searchpaths, true)
	if err != nil {
		return
	}
	pool, err = PoolOpen(name)
	return
}

// func PoolList(paths []string, cache string) (pools []Pool, err error) {
//
// }

// PoolOpenAll open all active ZFS pools on current system.
// Returns array of Pool handlers, each have to be closed after not needed
// anymore. Call Pool.Close() method.
func PoolOpenAll() (pools []Pool, err error) {
	var pool Pool
	if pool.list = C.zpool_list_openall(); pool.list == nil {
		err = LastError()
		return
	}
	for pool.list != nil {
		err = pool.ReloadProperties()
		if err != nil {
			return
		}
		next := C.zpool_next(pool.list)
		pool.list.pnext = nil
		pools = append(pools, pool)
		pool.list = next
	}
	return
}

// PoolCloseAll close all pools in given slice
func PoolCloseAll(pools []Pool) {
	for _, p := range pools {
		p.Close()
	}
}

// PoolPropertyToName convert property to name
// ( returns built in string representation of property name).
// This is optional, you can represent each property with string
// name of choice.
func PoolPropertyToName(p Prop) (name string) {
	if p == PoolNumProps {
		return "numofprops"
	}
	prop := C.zpool_prop_t(p)
	name = C.GoString(C.zpool_prop_to_name(prop))
	return
}

// PoolStateToName maps POOL STATE to string.
func PoolStateToName(state PoolState) (name string) {
	ps := C.pool_state_t(state)
	name = C.GoString(C.zpool_pool_state_to_name(ps))
	return
}

// RefreshStats the pool's vdev statistics, e.g. bytes read/written.
func (pool *Pool) RefreshStats() (err error) {
	if 0 != C.refresh_stats(pool.list) {
		return errors.New("error refreshing stats")
	}
	return nil
}

// ReloadProperties re-read ZFS pool properties and features, refresh
// Pool.Properties and Pool.Features map
func (pool *Pool) ReloadProperties() (err error) {
	propList := C.read_zpool_properties(pool.list)
	if propList == nil {
		err = LastError()
		return
	}

	pool.Properties = make([]Property, PoolNumProps+1)
	next := propList
	for i := 0; next != nil && i < int(PoolNumProps); i++ {
		pool.Properties[next.property] = Property{Value: C.GoString(&(next.value[0])), Source: C.GoString(&(next.source[0]))}
		next = C.next_property(next)
	}
	C.free_properties(propList)

	// read features
	pool.Features = map[string]string{
		"async_destroy":      "disabled",
		"empty_bpobj":        "disabled",
		"lz4_compress":       "disabled",
		"spacemap_histogram": "disabled",
		"enabled_txg":        "disabled",
		"hole_birth":         "disabled",
		"extensible_dataset": "disabled",
		"embedded_data":      "disabled",
		"bookmarks":          "disabled",
		"filesystem_limits":  "disabled",
		"large_blocks":       "disabled"}
	for name := range pool.Features {
		_, ferr := pool.GetFeature(name)
		if ferr != nil {
			// tolerate it
		}
	}
	return
}

// GetProperty reload and return single specified property. This also reloads requested
// property in Properties map.
func (pool *Pool) GetProperty(p Prop) (prop Property, err error) {
	if pool.list != nil {
		// First check if property exist at all
		if p < PoolPropName || p > PoolNumProps {
			err = errors.New(fmt.Sprint("Unknown zpool property: ",
				PoolPropertyToName(p)))
			return
		}
		list := C.read_zpool_property(pool.list, C.int(p))
		if list == nil {
			err = LastError()
			return
		}
		defer C.free_properties(list)
		prop.Value = C.GoString(&(list.value[0]))
		prop.Source = C.GoString(&(list.source[0]))
		pool.Properties[p] = prop
		return
	}
	return prop, errors.New(msgPoolIsNil)
}

// GetFeature reload and return single specified feature. This also reloads requested
// feature in Features map.
func (pool *Pool) GetFeature(name string) (value string, err error) {
	var fvalue [512]C.char
	csName := C.CString(fmt.Sprint("feature@", name))
	r := C.zpool_prop_get_feature(pool.list.zph, csName, &(fvalue[0]), 512)
	C.free(unsafe.Pointer(csName))
	if r != 0 {
		err = errors.New(fmt.Sprint("Unknown zpool feature: ", name))
		return
	}
	value = C.GoString(&(fvalue[0]))
	pool.Features[name] = value
	return
}

// SetProperty set ZFS pool property to value. Not all properties can be set,
// some can be set only at creation time and some are read only.
// Always check if returned error and its description.
func (pool *Pool) SetProperty(p Prop, value string) (err error) {
	if pool.list != nil {
		// First check if property exist at all
		if p < PoolPropName || p > PoolNumProps {
			err = errors.New(fmt.Sprint("Unknown zpool property: ",
				PoolPropertyToName(p)))
			return
		}
		csPropName := C.CString(PoolPropertyToName(p))
		csPropValue := C.CString(value)
		r := C.zpool_set_prop(pool.list.zph, csPropName, csPropValue)
		C.free(unsafe.Pointer(csPropName))
		C.free(unsafe.Pointer(csPropValue))
		if r != 0 {
			err = LastError()
		} else {
			// Update Properties member with change made
			if _, err = pool.GetProperty(p); err != nil {
				return
			}
		}
		return
	}
	return errors.New(msgPoolIsNil)
}

// Close ZFS pool handler and release associated memory.
// Do not use Pool object after this.
func (pool *Pool) Close() {
	if pool.list != nil {
		C.zpool_list_close(pool.list)
		pool.list = nil
	}
}

// Name get (re-read) ZFS pool name property
func (pool *Pool) Name() (name string, err error) {
	if pool.list == nil {
		err = errors.New(msgPoolIsNil)
	} else {
		name = C.GoString(C.zpool_get_name(pool.list.zph))
		pool.Properties[PoolPropName] = Property{Value: name, Source: "none"}
	}
	return
}

// State get ZFS pool state
// Return the state of the pool (ACTIVE or UNAVAILABLE)
func (pool *Pool) State() (state PoolState, err error) {
	if pool.list == nil {
		err = errors.New(msgPoolIsNil)
	} else {
		state = PoolState(C.zpool_read_state(pool.list.zph))
	}
	return
}

func (vdev *VDevTree) isGrouping() (grouping bool, mindevs, maxdevs int) {
	maxdevs = int(^uint(0) >> 1)
	if vdev.Type == VDevTypeRaidz {
		grouping = true
		if vdev.Parity == 0 {
			vdev.Parity = 1
		}
		if vdev.Parity > 254 {
			vdev.Parity = 254
		}
		mindevs = int(vdev.Parity) + 1
		maxdevs = 255
	} else if vdev.Type == VDevTypeMirror {
		grouping = true
		mindevs = 2
	} else if vdev.Type == VDevTypeLog || vdev.Type == VDevTypeSpare || vdev.Type == VDevTypeL2cache {
		grouping = true
		mindevs = 1
	}
	return
}

func (vdev *VDevTree) isLog() (r C.uint64_t) {
	r = 0
	if vdev.Type == VDevTypeLog {
		r = 1
	}
	return
}

func toCPoolProperties(props PoolProperties) (cprops C.nvlist_ptr) {
	cprops = C.new_property_nvlist()
	for prop, value := range props {
		name := C.zpool_prop_to_name(C.zpool_prop_t(prop))
		csPropValue := C.CString(value)
		r := C.property_nvlist_add(cprops, name, csPropValue)
		C.free(unsafe.Pointer(csPropValue))
		if r != 0 {
			if cprops != nil {
				C.nvlist_free(cprops)
				cprops = nil
			}
			return
		}
	}
	return
}

func toCDatasetProperties(props DatasetProperties) (cprops C.nvlist_ptr) {
	cprops = C.new_property_nvlist()
	for prop, value := range props {
		name := C.zfs_prop_to_name(C.zfs_prop_t(prop))
		csPropValue := C.CString(value)
		r := C.property_nvlist_add(cprops, name, csPropValue)
		C.free(unsafe.Pointer(csPropValue))
		if r != 0 {
			if cprops != nil {
				C.nvlist_free(cprops)
				cprops = nil
			}
			return
		}
	}
	return
}

func buildVdev(vdev VDevTree, ashift int) (nvvdev *C.struct_nvlist, err error) {
	if r := C.nvlist_alloc(&nvvdev, C.NV_UNIQUE_NAME, 0); r != 0 {
		err = errors.New("Failed to allocate vdev")
		return
	}
	csType := C.CString(string(vdev.Type))
	r := C.nvlist_add_string(nvvdev, C.sZPOOL_CONFIG_TYPE,
		csType)
	C.free(unsafe.Pointer(csType))
	if r != 0 {
		err = errors.New("Failed to set vdev type")
		return
	}
	if r := C.nvlist_add_uint64(nvvdev, C.sZPOOL_CONFIG_IS_LOG,
		vdev.isLog()); r != 0 {
		err = errors.New("Failed to allocate vdev (is_log)")
		return
	}
	if r := C.nvlist_add_uint64(nvvdev,
		C.sZPOOL_CONFIG_WHOLE_DISK, 1); r != 0 {
		err = errors.New("Failed to allocate vdev nvvdev (whdisk)")
		return
	}
	if len(vdev.Path) > 0 {
		csPath := C.CString(vdev.Path)
		r := C.nvlist_add_string(
			nvvdev, C.sZPOOL_CONFIG_PATH,
			csPath)
		C.free(unsafe.Pointer(csPath))
		if r != 0 {
			err = errors.New("Failed to allocate vdev nvvdev (type)")
			return
		}
		if ashift > 0 {
			if r := C.nvlist_add_uint64(nvvdev,
				C.sZPOOL_CONFIG_ASHIFT,
				C.uint64_t(ashift)); r != 0 {
				err = errors.New("Failed to allocate vdev nvvdev (ashift)")
				return
			}
		}
	}
	return
}

func buildVDevTree(root *C.nvlist_t, rtype VDevType, vdevs, spares, l2cache []VDevTree,
	props PoolProperties) (err error) {
	count := len(vdevs)
	if count == 0 {
		return
	}
	childrens := C.nvlist_alloc_array(C.int(count))
	if childrens == nil {
		err = errors.New("No enough memory")
		return
	}
	defer C.nvlist_free_array(childrens)
	for i, vdev := range vdevs {
		grouping, mindevs, maxdevs := vdev.isGrouping()
		var child *C.struct_nvlist
		vcount := len(vdev.Devices)
		if vcount < mindevs || vcount > maxdevs {
			err = fmt.Errorf(
				"Invalid vdev specification: %s supports no less than %d or more than %d devices",
				vdev.Type, mindevs, maxdevs)
			return
		}
		if grouping {
			if r := C.nvlist_alloc(&child, C.NV_UNIQUE_NAME, 0); r != 0 {
				err = errors.New("Failed to allocate vdev")
				return
			}
			csType := C.CString(string(vdev.Type))
			r := C.nvlist_add_string(child, C.sZPOOL_CONFIG_TYPE,
				csType)
			C.free(unsafe.Pointer(csType))
			if r != 0 {
				err = errors.New("Failed to set vdev type")
				return
			}
			if vdev.Type == VDevTypeRaidz {
				r := C.nvlist_add_uint64(child,
					C.sZPOOL_CONFIG_NPARITY,
					C.uint64_t(mindevs-1))
				if r != 0 {
					err = errors.New("Failed to allocate vdev (parity)")
					return
				}
			}
			if err = buildVDevTree(child, vdev.Type, vdev.Devices, nil, nil,
				props); err != nil {
				return
			}
		} else {
			ashift, _ := strconv.Atoi(props[PoolPropAshift])
			if child, err = buildVdev(vdev, ashift); err != nil {
				return
			}
		}
		C.nvlist_array_set(childrens, C.int(i), child)
	}
	if count > 0 {
		if r := C.nvlist_add_nvlist_array(root,
			C.sZPOOL_CONFIG_CHILDREN, childrens,
			C.uint_t(count)); r != 0 {
			err = errors.New("Failed to allocate vdev children")
			return
		}
	}
	if len(spares) > 0 {
		ashift, _ := strconv.Atoi(props[PoolPropAshift])
		if err = buildVdevSpares(root, VDevTypeRoot, spares, ashift); err != nil {
			return
		}
	}
	if len(l2cache) > 0 {
		ashift, _ := strconv.Atoi(props[PoolPropAshift])
		if err = buildVdevL2Cache(root, VDevTypeRoot, l2cache, ashift); err != nil {
			return
		}
	}
	return
}

func buildVdevSpares(root *C.nvlist_t, rtype VDevType, vdevs []VDevTree, ashift int) (err error) {
	count := len(vdevs)
	if count == 0 {
		return
	}
	spares := C.nvlist_alloc_array(C.int(count))
	if spares == nil {
		err = errors.New("No enough memory buildVdevSpares")
		return
	}
	defer C.nvlist_free_array(spares)
	for i, vdev := range vdevs {
		var child *C.struct_nvlist
		if child, err = buildVdev(vdev, ashift); err != nil {
			return
		}
		C.nvlist_array_set(spares, C.int(i), child)
	}
	if r := C.nvlist_add_nvlist_array(root,
		C.sZPOOL_CONFIG_SPARES, spares, C.uint_t(len(vdevs))); r != 0 {
		err = errors.New("Failed to allocate vdev spare")
	}
	return
}

func buildVdevL2Cache(root *C.nvlist_t, rtype VDevType, vdevs []VDevTree, ashift int) (err error) {
	count := len(vdevs)
	if count == 0 {
		return
	}
	l2cache := C.nvlist_alloc_array(C.int(count))
	if l2cache == nil {
		err = errors.New("No enough memory buildVdevL2Cache")
		return
	}
	defer C.nvlist_free_array(l2cache)
	for i, vdev := range vdevs {
		var child *C.struct_nvlist
		if child, err = buildVdev(vdev, ashift); err != nil {
			return
		}
		C.nvlist_array_set(l2cache, C.int(i), child)
	}
	if r := C.nvlist_add_nvlist_array(root,
		C.sZPOOL_CONFIG_SPARES, l2cache, C.uint_t(len(vdevs))); r != 0 {
		err = errors.New("Failed to allocate vdev l2cache")
	}
	return
}

// PoolCreate create ZFS pool per specs, features and properties of pool and root dataset
func PoolCreate(name string, vdev VDevTree, features map[string]string,
	props PoolProperties, fsprops DatasetProperties) (pool Pool, err error) {
	// create root vdev nvroot
	var nvroot *C.struct_nvlist
	if r := C.nvlist_alloc(&nvroot, C.NV_UNIQUE_NAME, 0); r != 0 {
		err = errors.New("Failed to allocate root vdev")
		return
	}
	csTypeRoot := C.CString(string(VDevTypeRoot))
	r := C.nvlist_add_string(nvroot, C.sZPOOL_CONFIG_TYPE,
		csTypeRoot)
	C.free(unsafe.Pointer(csTypeRoot))
	if r != 0 {
		err = errors.New("Failed to allocate root vdev")
		return
	}
	defer C.nvlist_free(nvroot)

	// Now we need to build specs (vdev hierarchy)
	if err = buildVDevTree(nvroot, VDevTypeRoot, vdev.Devices, vdev.Spares, vdev.L2Cache, props); err != nil {
		return
	}

	// Enable 0.6.5 features per default
	features["spacemap_histogram"] = FENABLED
	features["enabled_txg"] = FENABLED
	features["hole_birth"] = FENABLED
	features["extensible_dataset"] = FENABLED
	features["embedded_data"] = FENABLED
	features["bookmarks"] = FENABLED
	features["filesystem_limits"] = FENABLED
	features["large_blocks"] = FENABLED

	// Enable 0.7.x features per default
	features["multi_vdev_crash_dump"] = FENABLED
	features["large_dnode"] = FENABLED
	features["sha512"] = FENABLED
	features["skein"] = FENABLED
	features["edonr"] = FENABLED
	features["userobj_accounting"] = FENABLED

	// Enable 2.1.x features per default
	features["encryption"] = FENABLED
	features["project_quota"] = FENABLED
	features["device_removal"] = FENABLED
	features["obsolete_counts"] = FENABLED
	features["zpool_checkpoint"] = FENABLED
	features["spacemap_v2"] = FENABLED
	features["allocation_classes"] = FENABLED
	features["resilver_defer"] = FENABLED
	features["bookmark_v2"] = FENABLED
	features["redaction_bookmarks"] = FENABLED
	features["redacted_datasets"] = FENABLED
	features["bookmark_written"] = FENABLED
	features["log_spacemap"] = FENABLED
	features["livelist"] = FENABLED
	features["device_rebuild"] = FENABLED
	features["zstd_compress"] = FENABLED
	features["draid"] = FENABLED

	// convert properties
	cprops := toCPoolProperties(props)
	if cprops != nil {
		defer C.nvlist_free(cprops)
	} else if len(props) > 0 {
		err = errors.New("Failed to allocate pool properties")
		return
	}
	cfsprops := toCDatasetProperties(fsprops)
	if cfsprops != nil {
		defer C.nvlist_free(cfsprops)
	} else if len(fsprops) > 0 {
		err = errors.New("Failed to allocate FS properties")
		return
	}
	for fname, fval := range features {
		csName := C.CString(fmt.Sprintf("feature@%s", fname))
		csVal := C.CString(fval)
		r := C.property_nvlist_add(cprops, csName, csVal)
		C.free(unsafe.Pointer(csName))
		C.free(unsafe.Pointer(csVal))
		if r != 0 {
			if cprops != nil {
				C.nvlist_free(cprops)
				cprops = nil
			}
			return
		}
	}

	// Create actual pool then open
	csName := C.CString(name)
	defer C.free(unsafe.Pointer(csName))
	if r := C.zpool_create(C.libzfsHandle, csName, nvroot,
		cprops, cfsprops); r != 0 {
		err = LastError()
		err = errors.New(err.Error() + " (zpool_create)")
		return
	}

	// Open created pool and return handle
	pool, err = PoolOpen(name)
	return
}

// Status get pool status. Let you check if pool healthy.
func (pool *Pool) Status() (status PoolStatus, err error) {
	var msgid *C.char
	var reason C.zpool_status_t
	var errata C.zpool_errata_t
	if pool.list == nil {
		err = errors.New(msgPoolIsNil)
		return
	}
	reason = C.zpool_get_status(pool.list.zph, &msgid, &errata)
	status = PoolStatus(reason)
	return
}

// Destroy the pool.  It is up to the caller to ensure that there are no
// datasets left in the pool. logStr is optional if specified it is
// appended to ZFS history
func (pool *Pool) Destroy(logStr string) (err error) {
	if pool.list == nil {
		err = errors.New(msgPoolIsNil)
		return
	}
	csLog := C.CString(logStr)
	defer C.free(unsafe.Pointer(csLog))
	retcode := C.zpool_destroy(pool.list.zph, csLog)
	if retcode != 0 {
		err = LastError()
	}
	return
}

// Export exports the pool from the system.
// Before exporting the pool, all datasets within the pool are unmounted.
// A pool can not be exported if it has a shared spare that is currently
// being used.
func (pool *Pool) Export(force bool, log string) (err error) {
	var forcet C.boolean_t
	if force {
		forcet = 1
	}
	csLog := C.CString(log)
	defer C.free(unsafe.Pointer(csLog))
	if rc := C.zpool_disable_datasets(pool.list.zph, forcet); rc != 0 {
		err = LastError()
		return
	}
	if rc := C.zpool_export(pool.list.zph, forcet, csLog); rc != 0 {
		err = LastError()
	}
	return
}

// ExportForce hard force export of the pool from the system.
func (pool *Pool) ExportForce(log string) (err error) {
	csLog := C.CString(log)
	defer C.free(unsafe.Pointer(csLog))
	if rc := C.zpool_export_force(pool.list.zph, csLog); rc != 0 {
		err = LastError()
	}
	return
}

// VDevTree - Fetch pool's current vdev tree configuration, state and stats
func (pool *Pool) VDevTree() (vdevs VDevTree, err error) {
	var nvroot *C.struct_nvlist
	var poolName string
	config := C.zpool_get_config(pool.list.zph, nil)
	if config == nil {
		err = fmt.Errorf("Failed zpool_get_config")
		return
	}
	if C.nvlist_lookup_nvlist(config, C.sZPOOL_CONFIG_VDEV_TREE, &nvroot) != 0 {
		err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_VDEV_TREE)
		return
	}
	if poolName, err = pool.Name(); err != nil {
		return
	}
	if vdevs, err = poolGetConfig(poolName, nvroot); err != nil {
		return
	}
	vdevs.Spares, err = poolGetSpares(poolName, nvroot)
	vdevs.L2Cache, err = poolGetL2Cache(poolName, nvroot)
	return
}

// Initialize - initializes pool
func (pool *Pool) Initialize() (err error) {
	return pool.initialize(PoolInitializeStart)
}

// CancelInitialization - cancels ongoing initialization
func (pool *Pool) CancelInitialization() (err error) {
	return pool.initialize(PoolInitializeCancel)
}

// SuspendInitialization - suspends ongoing initialization
func (pool *Pool) SuspendInitialization() (err error) {
	return pool.initialize(PoolInitializeSuspend)
}

func (pool *Pool) initialize(action PoolInitializeAction) (err error) {
	var nvroot *C.struct_nvlist

	config := C.zpool_get_config(pool.list.zph, nil)
	if config == nil {
		err = fmt.Errorf("Failed zpool_get_config")
		return
	}
	if C.nvlist_lookup_nvlist(config, C.sZPOOL_CONFIG_VDEV_TREE, &nvroot) != 0 {
		err = fmt.Errorf("Failed to fetch %s", C.ZPOOL_CONFIG_VDEV_TREE)
		return
	}

	var vds *C.nvlist_t
	if r := C.nvlist_alloc(&vds, C.NV_UNIQUE_NAME, 0); r != 0 {
		err = errors.New("Failed to allocate vdev")
		return
	}
	defer C.nvlist_free(vds)

	C.collect_zpool_leaves(pool.list.zph, nvroot, vds)

	if C.zpool_initialize(pool.list.zph, C.pool_initialize_func_t(action), vds) != 0 {
		err = fmt.Errorf("Initialization action %s failed. (%s)", action.String(), LastError())
		return
	}
	return
}

func (s PoolState) String() string {
	switch s {
	case PoolStateActive:
		return "ACTIVE"
	case PoolStateExported:
		return "EXPORTED"
	case PoolStateDestroyed:
		return "DESTROYED"
	case PoolStateSpare:
		return "SPARE"
	case PoolStateL2cache:
		return "L2CACHE"
	case PoolStateUninitialized:
		return "UNINITIALIZED"
	case PoolStateUnavail:
		return "UNAVAILABLE"
	case PoolStatePotentiallyActive:
		return "POTENTIALLYACTIVE"
	default:
		return "UNKNOWN"
	}
}

func (s VDevState) String() string {
	switch s {
	case VDevStateUnknown:
		return "UNINITIALIZED"
	case VDevStateClosed:
		return "CLOSED"
	case VDevStateOffline:
		return "OFFLINE"
	case VDevStateRemoved:
		return "REMOVED"
	case VDevStateCantOpen:
		return "CANT_OPEN"
	case VDevStateFaulted:
		return "FAULTED"
	case VDevStateDegraded:
		return "DEGRADED"
	case VDevStateHealthy:
		return "ONLINE"
	default:
		return "UNKNOWN"
	}
}

func (s PoolStatus) String() string {
	str, known := PoolStatusStrings[s]
	if !known {
		return "UNKNOWN"
	}
	return str
}

func (s PoolInitializeAction) String() string {
	switch s {
	case PoolInitializeStart:
		return "START"
	case PoolInitializeCancel:
		return "CANCEL"
	case PoolInitializeSuspend:
		return "SUSPEND"
	default:
		return "UNKNOWN"
	}
}
