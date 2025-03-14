package edac

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	// root is the file root for edac sysfs devices.
	// It's a var not a const so we can test easily.
	root = "/sys/devices/system/edac/mc"

	// ErrMemoryNotSupported is returned if the system doesn't support EDAC memory.
	// If you get this error check your system has the EDAC kernel modules loaded.
	ErrMemoryNotSupported = errors.New("edac: memory not supported")
)

// MemoryController represents a memory controller.
type MemoryController struct {
	// Name is the name of the memory controller.
	Name string
}

// MemoryControllers returns the memory controllers available on the system.
// Returns ErrMemoryNotSupported if no EDAC memory support is detected.
func MemoryControllers() ([]MemoryController, error) {
	files, err := filepath.Glob(filepath.Join(root, "mc*"))
	if err != nil {
		return nil, err
	}

	if len(files) == 0 {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			return nil, ErrMemoryNotSupported
		}
		return nil, nil
	}

	mcs := make([]MemoryController, len(files))
	for i, n := range files {
		mcs[i] = NewMemoryController(strings.Replace(n, root+string(filepath.Separator), "", 1))
	}

	return mcs, nil
}

// NewMemoryController returns a memory controller for name.
func NewMemoryController(name string) MemoryController {
	return MemoryController{Name: name}
}

// loadInt64 loads an int64 from file into addr.
func (mc MemoryController) loadInt64(file string, addr *int64) error {
	var s string
	if err := mc.loadString(file, &s); err != nil {
		return err
	}

	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}

	*addr = v

	return nil
}

// loadString loads a string from file into addr.
func (mc MemoryController) loadString(file string, addr *string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}

	d, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	*addr = strings.TrimSpace(string(d))
	return nil
}

// Info returns the current information about the memory controller.
func (mc MemoryController) Info() (*MemoryInfo, error) {
	dir := filepath.Join(root, mc.Name)
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var names []string
	if names, err = f.Readdirnames(0); err != nil {
		return nil, err
	}

	i := &MemoryInfo{Name: mc.Name}
	for _, n := range names {
		p := filepath.Join(dir, n)
		switch n {
		case "seconds_since_reset":
			var v int64
			if err = mc.loadInt64(p, &v); err != nil {
				return nil, err
			}
			i.SinceReset = time.Duration(v) * time.Second
		case "ue_count":
			if err = mc.loadInt64(p, &i.Uncorrectable); err != nil {
				return nil, err
			}
		case "ue_noinfo_count":
			if err = mc.loadInt64(p, &i.UncorrectableNoInfo); err != nil {
				return nil, err
			}
		case "ce_count":
			if err = mc.loadInt64(p, &i.Correctable); err != nil {
				return nil, err
			}
		case "ce_noinfo_count":
			if err = mc.loadInt64(p, &i.CorrectableNoInfo); err != nil {
				return nil, err
			}
		case "size_mb":
			if err = mc.loadInt64(p, &i.Size); err != nil {
				return nil, err
			}
		case "sdram_scrub_rate":
			if err = mc.loadInt64(p, &i.ScrubRate); err != nil {
				return nil, err
			}
		case "mc_name":
			if err = mc.loadString(p, &i.Type); err != nil {
				return nil, err
			}
		case "max_location":
			if err = mc.loadString(p, &i.MaxLocation); err != nil {
				return nil, err
			}
		}
	}

	return i, nil
}

// DimmRanks returns the DimmRanks for the memory controller.
func (mc MemoryController) DimmRanks() ([]DimmRank, error) {
	dimms, err := filepath.Glob(filepath.Join(root, mc.Name, "dimm*"))
	if err != nil {
		return nil, err
	}

	ranks, err := filepath.Glob(filepath.Join(root, mc.Name, "ranks*"))
	if err != nil {
		return nil, err
	}

	dirs := append(dimms, ranks...)
	drs := make([]DimmRank, len(dirs))
	for i, p := range dirs {
		dr, err := mc.dimmRank(p)
		if err != nil {
			return nil, err
		}
		drs[i] = *dr
	}

	return drs, nil
}

// dimmRanks creates a DimmRank from the data in dir.
func (mc MemoryController) dimmRank(dir string) (*DimmRank, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var names []string
	if names, err = f.Readdirnames(0); err != nil {
		return nil, err
	}

	dr := &DimmRank{Name: filepath.Base(dir)}
	for _, n := range names {
		p := filepath.Join(dir, n)
		switch n {
		case "size":
			if err = mc.loadInt64(p, &dr.Size); err != nil {
				return nil, err
			}
		case "dimm_dev_type":
			if err = mc.loadString(p, &dr.DeviceType); err != nil {
				return nil, err
			}
		case "dimm_edac_mode":
			if err = mc.loadString(p, &dr.Mode); err != nil {
				return nil, err
			}
		case "dimm_label":
			if err = mc.loadString(p, &dr.Label); err != nil {
				return nil, err
			}
		case "dimm_location":
			if err = mc.loadString(p, &dr.Location); err != nil {
				return nil, err
			}
		case "dimm_mem_type":
			if err = mc.loadString(p, &dr.MemoryType); err != nil {
				return nil, err
			}
		case "dimm_ce_count":
			if err = mc.loadInt64(p, &dr.Correctable); err != nil {
				return nil, err
			}
		case "dimm_ue_count":
			if err = mc.loadInt64(p, &dr.Uncorrectable); err != nil {
				return nil, err
			}
		}
	}

	return dr, nil
}

// ResetCounters will zero all the statistical counters for UE and CE errors
// on the given memory controller. Zeroing the counters will also reset the
// timer indicating how long since the last counter were reset. This is useful
// for computing errors/time. Since the counters are always reset at driver
// initialization time, no module/kernel parameter is available.
func (mc *MemoryController) ResetCounters() error {
	f, err := os.OpenFile(filepath.Join(root, mc.Name, "reset_counters"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte("1"))
	return err
}

// SetScrubRate sets the minimum bandwidth in bytes/sec.
// The rate will be translated to an internal value that gives at least the specified rate.
func (mc *MemoryController) SetScrubRate(bytesPerSec uint) error {
	f, err := os.OpenFile(filepath.Join(root, mc.Name, "sdram_scrub_rate"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write([]byte(strconv.FormatUint(uint64(bytesPerSec), 10)))
	return err
}
