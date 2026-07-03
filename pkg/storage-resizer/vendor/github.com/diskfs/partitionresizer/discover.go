package partitionresizer

import (
	"bufio"
	"bytes"
	"errors"
	iofs "io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/backend/file"
	"github.com/diskfs/go-diskfs/partition/gpt"
)

const (
	sysDefaultPath = "/sys"
)

// findDisks find all disks and their partitions, including reference name and partition position.
// Does so entirely via sysfs. If the 'disk' parameter is non-empty,
// scans for all disks, otherwise just for the given disk. Example, if disk is "/dev/sda", only /sys/class/block/sda is scanned,
// otherwise all disks under /sys/class/block are scanned.
//
// If the 'syspath' parameter is non-empty, uses that as the base sysfs path instead of /sys.
//
// If the 'disk' parameter is not a device, but rather an image file, i.e. cannot be found under /sys/class/block,
// then it tries to get partition data by scanning it as a disk image directly. In that case, the
// identifier ByName is not valid, since that name only is relevant for block devices recognized by the kernel
// and visible via sysfs.
func findDisks(disk, syspath string) (map[string][]partitionData, error) {
	var (
		candidates []iofs.FileInfo
	)
	if syspath == "" {
		syspath = sysDefaultPath
	}
	sysClassBlockPath := filepath.Join(syspath, "class", "block")
	// which candidates to check, depends if we were given a specific disk or not
	if disk != "" {
		// only check the given disk, which might be a device or an image file
		base := filepath.Base(disk)
		diskSysPath := filepath.Join(sysClassBlockPath, base)
		info, err := os.Stat(diskSysPath)
		switch {
		case err != nil && !errors.Is(err, iofs.ErrNotExist):
			return nil, err
		case err != nil:
			// file does not exist under sysfs, so try to open as disk image and get partition info that way
			f, err := os.Open(disk)
			if err != nil {
				return nil, err
			}
			backend := file.New(f, false)
			d, err := diskfs.OpenBackend(backend)
			if err != nil {
				return nil, err
			}
			tableRaw, err := d.GetPartitionTable()
			if err != nil {
				return nil, err
			}
			table, ok := tableRaw.(*gpt.Table)
			if !ok {
				return nil, errors.New("unsupported partition table type, only GPT is supported")
			}
			var parts []partitionData
			for _, p := range table.Partitions {
				// no name field
				start := int64(p.Start) * int64(d.LogicalBlocksize)
				pd := partitionData{
					label:  p.Name,
					uuid:   p.UUID(),
					size:   p.GetSize(),
					start:  start,
					end:    start + p.GetSize() - 1,
					number: p.Index,
				}
				parts = append(parts, pd)
			}
			allDisks := make(map[string][]partitionData)
			allDisks[base] = parts
			return allDisks, nil
		default:
			candidates = append(candidates, info)
		}
	} else {
		// check all findDisks
		candidatesDE, err := os.ReadDir(sysClassBlockPath)
		if err != nil {
			return nil, err
		}
		for _, de := range candidatesDE {
			info, err := de.Info()
			if err != nil {
				return nil, err
			}
			candidates = append(candidates, info)
		}
	}
	var allDisks = make(map[string][]partitionData)
	for _, candidate := range candidates {
		if !candidate.IsDir() {
			continue
		}
		// we only care about disk types
		// - has partition child, is a partition
		// - has a loop child, is a loop
		// - has a dm child, is a device-mapper
		// - starts with "ram", is a ramdisk
		// - has a comp_algorithm child, is a zramdisk
		// - else is just a disk
		children, err := os.ReadDir(filepath.Join(sysClassBlockPath, candidate.Name()))
		if err != nil {
			return nil, err
		}
		isDisk := true
		for _, child := range children {
			name := child.Name()
			switch {
			case name == "partition":
				isDisk = false
			case name == "loop":
				isDisk = false
			case name == "dm":
				isDisk = false
			case len(name) >= 3 && name[0:3] == "ram":
				isDisk = false
			case name == "comp_algorithm":
				isDisk = false
			default:
				continue
			}
			if !isDisk {
				break
			}
		}
		// if we got this far, nothing caused it to break, so it's a disk
		if !isDisk {
			continue
		}
		// get the logical block size
		blockSize, err := readSysIntValue(filepath.Join(sysClassBlockPath, candidate.Name(), "queue", "logical_block_size"))
		if err != nil {
			return nil, err
		}

		// find all of the child partitions, and store them in the right order
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			name := child.Name()
			// find partition children
			partitionInfoFile := filepath.Join(sysClassBlockPath, candidate.Name(), name, "partition")
			if _, err := os.Stat(partitionInfoFile); err != nil {
				// not a partition
				continue
			}
			// read partition info: number, size, start
			id, err := readSysIntValue(partitionInfoFile)
			if err != nil {
				return nil, err
			}
			size, err := readSysIntValue(filepath.Join(sysClassBlockPath, candidate.Name(), name, "size"))
			if err != nil {
				return nil, err
			}
			start, err := readSysIntValue(filepath.Join(sysClassBlockPath, candidate.Name(), name, "start"))
			if err != nil {
				return nil, err
			}
			// sysfs reports `size` as the partition's length in sectors
			// (not its last LBA), so the inclusive last sector is
			// start + size - 1. The disk-image branch above uses the
			// same formula.
			end := start + size - 1
			// read from uevent to get name
			ueventPath := filepath.Join(sysClassBlockPath, candidate.Name(), name, "uevent")
			ueventData, err := os.ReadFile(ueventPath)
			if err != nil {
				return nil, err
			}
			ue := parseKeyValueLines(ueventData)
			label := ue["PARTNAME"]
			// go-diskfs (image path) reports GUIDs upper-cased; match it so
			// the same identifier compares equal on both discovery paths.
			uuid := strings.ToUpper(ue["PARTUUID"])
			pd := partitionData{
				name:   name,
				label:  label,
				uuid:   uuid,
				size:   size * blockSize,
				start:  start * blockSize,
				end:    end * blockSize,
				number: int(id),
			}
			allDisks[candidate.Name()] = append(allDisks[candidate.Name()], pd)
		}
	}
	return allDisks, nil
}

// filterDisksByPartitions returns all of the disks that have all of the given partition identifiers
func filterDisksByPartitions(disks map[string][]partitionData, partIdentifiers []PartitionIdentifier) ([]string, error) {
	var found []string
	for disk, parts := range disks {
		matchedAll := true
		for _, pi := range partIdentifiers {
			matched := false
			for _, p := range parts {
				switch pi.By() {
				case IdentifierByName:
					if p.name == pi.Value() {
						matched = true
					}
				case IdentifierByLabel:
					if p.label == pi.Value() {
						matched = true
					}
				case IdentifierByUUID:
					if p.uuid == pi.Value() {
						matched = true
					}
				}
				if matched {
					break
				}
			}
			if !matched {
				matchedAll = false
				break
			}
		}
		if matchedAll {
			found = append(found, disk)
		}
	}
	return found, nil
}

func readSysIntValue(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	// trim newline or carriage return
	s := string(data)
	if len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return strconv.ParseInt(s, 10, 64)
}

// parseKeyValueLines parses the contents of key=value lines
// (KEY=VALUE\n...) into a map.
// Lines without '=' are ignored.
func parseKeyValueLines(data []byte) map[string]string {
	m := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		m[key] = val
	}
	return m
}
