package conntrack

import (
	"fmt"

	"github.com/mdlayher/netlink"

	"github.com/ti-mo/netfilter"
)

// Stats represents the Conntrack performance counters of a single CPU (core).
// It indicates which and how many Flow operations took place on each CPU.
type Stats struct {
	CPUID         uint16
	Found         uint32
	Invalid       uint32
	Ignore        uint32
	Insert        uint32
	InsertFailed  uint32
	Drop          uint32
	EarlyDrop     uint32
	Error         uint32
	SearchRestart uint32
}

func (s Stats) String() string {
	return fmt.Sprintf(
		"<CPU %d - Found: %d, Invalid: %d, Ignore: %d, Insert: %d, InsertFailed: %d, Drop: %d, EarlyDrop: %d, Error: %d, SearchRestart: %d>",
		s.CPUID, s.Found, s.Invalid, s.Ignore, s.Insert, s.InsertFailed, s.Drop, s.EarlyDrop, s.Error, s.SearchRestart,
	)
}

// unmarshal unmarshals a list of netfilter.Attributes into a Stats structure.
func (s *Stats) unmarshal(attrs []netfilter.Attribute) {

	for _, attr := range attrs {
		switch at := cpuStatsType(attr.Type); at {
		case ctaStatsFound:
			s.Found = attr.Uint32()
		case ctaStatsInvalid:
			s.Invalid = attr.Uint32()
		case ctaStatsIgnore:
			s.Ignore = attr.Uint32()
		case ctaStatsInsert:
			s.Insert = attr.Uint32()
		case ctaStatsInsertFailed:
			s.InsertFailed = attr.Uint32()
		case ctaStatsDrop:
			s.Drop = attr.Uint32()
		case ctaStatsEarlyDrop:
			s.EarlyDrop = attr.Uint32()
		case ctaStatsError:
			s.Error = attr.Uint32()
		case ctaStatsSearchRestart:
			s.SearchRestart = attr.Uint32()
		case ctaStatsSearched, ctaStatsNew, ctaStatsDelete, ctaStatsDeleteList:
			// Deprecated performance counters, not parsed into Stats.
			// See torvalds/linux@8e8118f.
		}
	}
}

// StatsExpect represents the Conntrack Expect performance counters of a single CPU (core).
// It indicates how many Expect entries were initialized, created or deleted on each CPU.
type StatsExpect struct {
	CPUID               uint16
	New, Create, Delete uint32
}

// unmarshal unmarshals a list of netfilter.Attributes into a StatsExpect structure.
func (se *StatsExpect) unmarshal(attrs []netfilter.Attribute) {

	for _, attr := range attrs {
		switch at := expectStatsType(attr.Type); at {
		case ctaStatsExpNew:
			se.New = attr.Uint32()
		case ctaStatsExpCreate:
			se.Create = attr.Uint32()
		case ctaStatsExpDelete:
			se.Delete = attr.Uint32()
		}
	}
}

// StatsGlobal represents global statistics about the conntrack subsystem.
type StatsGlobal struct {
	Entries, MaxEntries uint32
}

// unmarshal unmarshals a list of netfilter.Attributes into a Stats structure.
func (sg *StatsGlobal) unmarshal(attrs []netfilter.Attribute) {

	for _, attr := range attrs {
		switch at := globalStatsType(attr.Type); at {
		case ctaStatsGlobalEntries:
			sg.Entries = attr.Uint32()
		case ctaStatsGlobalMaxEntries:
			sg.MaxEntries = attr.Uint32()
		}
	}
}

// unmarshalStats unmarshals a list of Stats from a list of netlink.Messages.
func unmarshalStats(nlm []netlink.Message) ([]Stats, error) {

	stats := make([]Stats, len(nlm))

	for idx, m := range nlm {

		hdr, nfa, err := netfilter.UnmarshalNetlink(m)
		if err != nil {
			return nil, err
		}

		s := Stats{CPUID: hdr.ResourceID}
		s.unmarshal(nfa)

		stats[idx] = s
	}

	return stats, nil
}

// unmarshalStatsExpect unmarshals a list of StatsExpect from a list of netlink.Messages.
func unmarshalStatsExpect(nlm []netlink.Message) ([]StatsExpect, error) {

	stats := make([]StatsExpect, len(nlm))

	for idx, m := range nlm {

		hdr, nfa, err := netfilter.UnmarshalNetlink(m)
		if err != nil {
			return nil, err
		}

		se := StatsExpect{CPUID: hdr.ResourceID}
		se.unmarshal(nfa)

		stats[idx] = se
	}

	return stats, nil
}

// unmarshalStatsGlobal unmarshals a StatsGlobal from a netlink.Message.
func unmarshalStatsGlobal(nlm netlink.Message) (StatsGlobal, error) {

	var sg StatsGlobal

	_, nfa, err := netfilter.UnmarshalNetlink(nlm)
	if err != nil {
		return sg, err
	}

	sg.unmarshal(nfa)

	return sg, nil
}
