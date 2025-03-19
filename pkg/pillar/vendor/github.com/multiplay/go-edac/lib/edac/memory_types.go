package edac

import (
	"fmt"
	"time"
)

// Information for these types was sourced from:
// https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-devices-edac

// MemoryInfo represents information about a memory controller.
type MemoryInfo struct {
	// Name is the name of memory controller which generated this
	// MemoryInfo.
	Name string

	// SinceReset is how long has elapsed since the last counter
	// reset. This can be used with the error counters to measure
	// error rates.
	SinceReset time.Duration `file:"seconds_since_reset"`

	// Type is the type of memory controller that is being utilized.
	Type string `file:"mc_name"`

	// Size in megabytes, of memory that this instance of memory
	// controller manages.
	Size int64 `file:"size_mb"`

	// Uncorrectable is the total count of uncorrectable errors that
	// have occurred on this memory controller.
	// If panic_on_ue is set this counter will not have a chance to
	// increment, since EDAC will panic the system.
	Uncorrectable int64 `file:"ue_count"`

	// UncorrectableNoInfo is the number of UEs that have occurred
	// with no information as to which DIMM slot is having errors.
	UncorrectableNoInfo int64 `file:"ue_noinfo_count"`

	// Correctable is the total count of correctable errors that have
	// occurred on this memory controller. This count is very important
	// to examine. Correctable errors provide early indications that a
	// DIMM is beginning to fail. This count field should be monitored
	// for non-zero values and report such information to the system
	// administrator.
	Correctable int64 `file:"ce_count"`

	// CorrectableNoInfo is the number of correctable errors that have
	// occurred with no information as to which DIMM slot is having errors.
	// Memory is handicapped, but operational, yet no information is
	// available to indicate which slot the failing memory is in. This
	// count field should be also be monitored for non-zero values.
	CorrectableNoInfo int64 `file:"ce_noinfo_count"`

	// ScrubRate is the actual scrubbing rate in bytes per second.
	//
	// If configuration fails or memory scrubbing is not implemented,
	// then the value will be -1.
	ScrubRate int64 `file:"sdram_scrub_rate"`

	// MaxLocation is the last available memory slot in this memory
	// controller. It is used by userspace tools in order to display the
	// memory filling layout.
	MaxLocation string `file:"max_location"`
}

// HasErrors returns true if mi has any errors, false otherwise.
func (mi MemoryInfo) HasErrors() bool {
	switch {
	case mi.Correctable != 0:
		return true
	case mi.CorrectableNoInfo != 0:
		return true
	case mi.Uncorrectable != 0:
		return true
	case mi.UncorrectableNoInfo != 0:
		return true
	}
	return false
}

// String implements Stringer.
func (mi MemoryInfo) String() string {
	return fmt.Sprintf(
		"%s - %d MB, %d correctable, %d correctable no info, %d uncorrectable, %d uncorrectable no info",
		mi.Name,
		mi.Size,
		mi.Correctable,
		mi.CorrectableNoInfo,
		mi.Uncorrectable,
		mi.UncorrectableNoInfo,
	)
}

// DimmRank represents a dimm or rank.
type DimmRank struct {
	// Name is the name of dimm or rank.
	Name string

	// Size is the size in MB of dimm or rank.
	// For dimm*/size, this is the size, in MB of the DIMM memory stick.
	//
	// For rank*/size, this is the size, in MB for one rank of the DIMM
	// memory stick.
	// On single rank memories (1R), this is also the total size of the dimm.
	// On dual rank (2R) memories, this is half the size of the total DIMM
	// memories.
	Size int64 `file:"size"`

	// DeviceType is type of DRAM device is being utilized on this DIMM
	// (x1, x2, x4, x8, ...).
	DeviceType string `file:"dimm_dev_type"`

	// Mode is the type of Error detection and correction is being utilized.
	// For example: S4ECD4ED would mean a Chipkill with x4 DRAM.
	Mode string `file:"dimm_edac_mode"`

	// Label is the DIMM's assigned label.
	// With this label in the module, when errors occur the output can provide
	// the DIMM label in the system log.
	//
	// This becomes vital for panic events to isolate the cause of the UE event.
	// DIMM Labels must be assigned after booting, with information that correctly
	// identifies the physical slot with its/ silk screen label. This information
	// is currently very motherboard specific and determination of this information
	// must occur in userland at this time.
	Label string `file:"dimm_label"`

	// Location is the location (csrow/channel, branch/channel/slot or channel/slot)
	// of the dimm or rank.
	Location string `file:"dimm_location"`

	// MemoryType is the type of memory is currently on this csrow. Normally, either
	// buffered or unbuffered memory (for example, Unbuffered-DDR3).
	MemoryType string `file:"dimm_mem_type"`

	// Correctable is the total count of correctable errors that have occurred
	// on this DIMM. This count is very important to examine. CEs provide early
	// indications that a DIMM is beginning to fail. This count field should be
	// monitored for non-zero values and report such information to the system
	// administrator.
	Correctable int64 `file:"dimm_ce_count"`

	// Uncorrectable is the total count of uncorrectable errors that have
	// occurred on this DIMM. If panic_on_ue is set, this counter will not have a
	// chance to increment, since EDAC will panic the system.
	Uncorrectable int64 `file:"dimm_ue_count"`
}

// HasErrors returns true if mi has any errors, false otherwise.
func (dr DimmRank) HasErrors() bool {
	switch {
	case dr.Correctable != 0:
		return true
	case dr.Uncorrectable != 0:
		return true
	}
	return false
}

// String implements Stringer.
func (dr DimmRank) String() string {
	return fmt.Sprintf(
		"%s - %d MB, %d correctable, %d uncorrectable",
		dr.Name,
		dr.Size,
		dr.Correctable,
		dr.Uncorrectable,
	)
}
