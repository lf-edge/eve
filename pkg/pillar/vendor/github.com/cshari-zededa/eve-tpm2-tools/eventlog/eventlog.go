// SPDX-License-Identifier: Apache-2.0

package eventlog

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	//"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strings"
)

type EventType uint32
type HashAlg uint8
type Algorithm uint16

const eventTypeNoAction = 0x03

const (
	PrebootCert          EventType = 0x00000000
	PostCode             EventType = 0x00000001
	unused               EventType = 0x00000002
	NoAction             EventType = 0x00000003
	Separator            EventType = 0x00000004
	Action               EventType = 0x00000005
	EventTag             EventType = 0x00000006
	SCRTMContents        EventType = 0x00000007
	SCRTMVersion         EventType = 0x00000008
	CpuMicrocode         EventType = 0x00000009
	PlatformConfigFlags  EventType = 0x0000000A
	TableOfDevices       EventType = 0x0000000B
	CompactHash          EventType = 0x0000000C
	Ipl                  EventType = 0x0000000D
	IplPartitionData     EventType = 0x0000000E
	NonhostCode          EventType = 0x0000000F
	NonhostConfig        EventType = 0x00000010
	NonhostInfo          EventType = 0x00000011
	OmitBootDeviceEvents EventType = 0x00000012
)

const (
	EFIEventBase               EventType = 0x80000000
	EFIVariableDriverConfig    EventType = 0x80000001
	EFIVariableBoot            EventType = 0x80000002
	EFIBootServicesApplication EventType = 0x80000003
	EFIBootServicesDriver      EventType = 0x80000004
	EFIRuntimeServicesDriver   EventType = 0x80000005
	EFIGPTEvent                EventType = 0x80000006
	EFIAction                  EventType = 0x80000007
	EFIPlatformFirmwareBlob    EventType = 0x80000008
	EFIHandoffTables           EventType = 0x80000009
	EFIHCRTMEvent              EventType = 0x80000010
	EFIVariableAuthority       EventType = 0x800000e0
)

var eventTypeNames = map[EventType]string{
	PrebootCert:          "Preboot Cert",
	PostCode:             "POST Code",
	unused:               "Unused",
	NoAction:             "No Action",
	Separator:            "Separator",
	Action:               "Action",
	EventTag:             "Event Tag",
	SCRTMContents:        "S-CRTM Contents",
	SCRTMVersion:         "S-CRTM Version",
	CpuMicrocode:         "CPU Microcode",
	PlatformConfigFlags:  "Platform Config Flags",
	TableOfDevices:       "Table of Devices",
	CompactHash:          "Compact Hash",
	Ipl:                  "IPL",
	IplPartitionData:     "IPL Partition Data",
	NonhostCode:          "Non-Host Code",
	NonhostConfig:        "Non-HostConfig",
	NonhostInfo:          "Non-Host Info",
	OmitBootDeviceEvents: "Omit Boot Device Events",

	EFIEventBase:               "EFI Event Base",
	EFIVariableDriverConfig:    "EFI Variable Driver Config",
	EFIVariableBoot:            "EFI Variable Boot",
	EFIBootServicesApplication: "EFI Boot Services Application",
	EFIBootServicesDriver:      "EFI Boot Services Driver",
	EFIRuntimeServicesDriver:   "EFI Runtime Services Driver",
	EFIGPTEvent:                "EFI GPT Event",
	EFIAction:                  "EFI Action",
	EFIPlatformFirmwareBlob:    "EFI Platform Firmware Blob",
	EFIVariableAuthority:       "EFI Variable Authority",
	EFIHandoffTables:           "EFI Handoff Tables",
	EFIHCRTMEvent:              "EFI H-CRTM Event",
}

type Digest struct {
	Hash crypto.Hash
	Data []byte
}

type Event struct {
	Sequence int
	Index    int
	Typ      EventType
	Data     []byte
	Digests  []Digest
}

type rawEventHeader struct {
	PCRIndex  uint32
	Type      uint32
	Digest    [20]byte
	EventSize uint32
}

type rawEvent2Header struct {
	PCRIndex uint32
	Type     uint32
}

type SpecIDHdr struct {
	Sign  [16]byte
	Pc    uint32
	VMi   uint8
	VMa   uint8
	Erta  uint8
	Siz   uint8
	NAlgs uint32
}

type SpecIDEvent struct {
	algs []SpecAlgSize
}

type SpecAlgSize struct {
	ID   Algorithm
	Size uint16
}

const (
	AlgSHA1   Algorithm = 0x0004
	AlgSHA256 Algorithm = 0x000B
)

// Valid hash algorithms.
var (
	HashSHA1   = HashAlg(AlgSHA1)
	HashSHA256 = HashAlg(AlgSHA256)
)

func (a HashAlg) cryptoHash() crypto.Hash {
	switch a {
	case HashSHA1:
		return crypto.SHA1
	case HashSHA256:
		return crypto.SHA256
	}
	return 0
}

func (a HashAlg) goTPMAlg() Algorithm {
	switch a {
	case HashSHA1:
		return AlgSHA1
	case HashSHA256:
		return AlgSHA256
	}
	return 0
}

// String returns a human-friendly representation of the hash algorithm.
func (a HashAlg) String() string {
	switch a {
	case HashSHA1:
		return "SHA1"
	case HashSHA256:
		return "SHA256"
	}
	return fmt.Sprintf("HashAlg<%d>", int(a))
}

func parseSpecIDEvent(data []byte) (SpecIDEvent, error) {
	treader := bytes.NewReader(data)
	var hdr SpecIDHdr
	if err := binary.Read(treader, binary.LittleEndian, &hdr); err != nil {
		return SpecIDEvent{}, err
	}
	sa := SpecAlgSize{}
	var specID SpecIDEvent
	for i := 0; i < int(hdr.NAlgs); i++ {
		if err := binary.Read(treader, binary.LittleEndian, &sa); err != nil {
			return SpecIDEvent{}, err
		}
		specID.algs = append(specID.algs, sa)
	}
	fmt.Println(specID)
	return specID, nil
}

func getSpecIDEvent(r *bytes.Buffer) (Event, error) {
	var h rawEventHeader
	var event Event
	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	if h.EventSize == 0 {
		return event, errors.New("event data size is 0")
	}
	if h.EventSize > uint32(r.Len()) {
		return event, fmt.Errorf("Event Size error")
	}

	data := make([]byte, int(h.EventSize))
	if _, err := io.ReadFull(r, data); err != nil {
		return event, err
	}

	digests := []Digest{{Hash: crypto.SHA1, Data: h.Digest[:]}}

	return Event{
		Typ:     EventType(h.Type),
		Data:    data,
		Index:   int(h.PCRIndex),
		Digests: digests,
	}, nil
}

func parseEvent(r *bytes.Buffer, specID SpecIDEvent) (Event, error) {
	var h rawEvent2Header

	var event Event

	if err := binary.Read(r, binary.LittleEndian, &h); err != nil {
		return event, err
	}
	event.Typ = EventType(h.Type)
	event.Index = int(h.PCRIndex)

	// parse the event digests
	var numDigests uint32
	if err := binary.Read(r, binary.LittleEndian, &numDigests); err != nil {
		return event, err
	}

	for i := 0; i < int(numDigests); i++ {
		var algID Algorithm
		if err := binary.Read(r, binary.LittleEndian, &algID); err != nil {
			return event, err
		}
		var digest Digest

		for _, alg := range specID.algs {
			if alg.ID != algID {
				continue
			}
			if uint16(r.Len()) < alg.Size {
				return event, fmt.Errorf("reading digest: %v", io.ErrUnexpectedEOF)
			}
			digest.Data = make([]byte, alg.Size)
			digest.Hash = HashAlg(alg.ID).cryptoHash()
		}
		if len(digest.Data) == 0 {
			return event, fmt.Errorf("unknown algorithm ID %x", algID)
		}
		if _, err := io.ReadFull(r, digest.Data); err != nil {
			return event, err
		}
		event.Digests = append(event.Digests, digest)
	}

	// parse event data
	var eventSize uint32
	if err := binary.Read(r, binary.LittleEndian, &eventSize); err != nil {
		return event, err
	}
	if eventSize == 0 {
		return event, errors.New("event data size is 0")
	}
	event.Data = make([]byte, int(eventSize))
	if _, err := io.ReadFull(r, event.Data); err != nil {
		return event, err
	}
	return event, nil
}

func isSha256Enabled(specID SpecIDEvent) bool {
	for _, alg := range specID.algs {
		if alg.ID == AlgSHA256 {
			return true
		}
	}
	return false
}

func (e *Event) Sha256Digest() []byte {
	for _, digest := range e.Digests {
		if digest.Hash == crypto.SHA256 {
			return digest.Data
		}
	}
	return []byte{}
}

func ParseEvents(eventLogFile string) ([]Event, error) {
	eventLogBytes, err := ioutil.ReadFile(eventLogFile)
	if err != nil {
		return nil, err
	}
	r := bytes.NewBuffer(eventLogBytes)
	event, err := getSpecIDEvent(r)
	if err != nil {
		return nil, err
	}
	specID, err := parseSpecIDEvent(event.Data)
	if err != nil {
		return nil, err
	}
	if isSha256Enabled(specID) == false {
		return nil, fmt.Errorf("SHA256 PCR bank not enabled")
	}
	var events []Event
	if event.Typ == eventTypeNoAction {
		sequence := 1
		for r.Len() > 0 {
			event, err := parseEvent(r, specID)
			if err != nil {
				return events, err
			}
			event.Sequence = sequence
			events = append(events, event)
			sequence++
		}
	}
	return events, nil
}

func EventLogIterate(events []Event) map[int][]byte {
	pcrs := make(map[int][]byte)
	for i := 0; i < 10; i++ {
		pcrs[i] = make([]byte, 32)
	}
	for _, event := range events {
		h := sha256.New()
		h.Write(event.Data)
		for _, digest := range event.Digests {
			if digest.Hash == crypto.SHA256 {
				extendBuf := sha256.New()
				extendBuf.Write(pcrs[event.Index])
				extendBuf.Write(digest.Data)
				pcrs[event.Index] = extendBuf.Sum(nil)
			}
		}
	}
	fmt.Println("Expected PCR values, as per eventlog:")
	for i := 0; i < 10; i++ {
		fmt.Printf("PCR%d: %x\n", i, pcrs[i])
	}
	return pcrs
}

const (
	ImgA = "IMGA"
	ImgB = "IMGB"
)

var diskGuids = make(map[string]Guid)

func ParseGPTEntries(events []Event) {
	for _, event := range events {
		if event.Index == 5 {
			gptEntries, err := parseGPTData(event.Data)
			if err == nil {
				diskGuids[ImgA] = gptEntries.ImgGuid(ImgA)
				diskGuids[ImgB] = gptEntries.ImgGuid(ImgB)
			}
		}
	}
}

func DumpEventLog(events []Event, verbose bool) {
	for _, event := range events {
		fmt.Printf("----Event %d----\n", event.Sequence)
		fmt.Printf("Type: %s\n", eventTypeNames[event.Typ])
		fmt.Printf("PCR:  %d\n", event.Index)
		h := sha256.New()
		h.Write(event.Data)
		fmt.Printf("Computed Hash: %x\n", h.Sum(nil))
		if verbose {
			if event.Index == 8 || event.Index == 9 {
				fmt.Printf("Data: %s\n", event.Data)
			}
			if err := parseEventDataTCG(event.Typ, event.Data); err != nil {
				fmt.Printf("Error in parseEventDataTCG: %v\n", err)
			}
		}
		for _, digest := range event.Digests {
			if digest.Hash == crypto.SHA256 {
				fmt.Printf("Digest: %x\n", digest.Data)
			}
		}
	}
}

func parseEventDataTCG(eventType EventType, data []byte) error {
	switch eventType {
	case NoAction, Action, Separator, EFIAction:
		return nil
	case EFIVariableDriverConfig, EFIVariableBoot, EFIVariableAuthority:
		return parseEventDataEFIVariable(data, eventType)
	case EFIBootServicesApplication, EFIBootServicesDriver, EFIRuntimeServicesDriver:
		return parseEventDataEFIImageLoad(data)
	case EFIGPTEvent:
		return parseEventDataEFIGPT(data)
	default:
	}
	return nil
}

// Guid corresponds to the EFI_GUID type
type Guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

func (g *Guid) String() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		g.Data1, g.Data2, g.Data3,
		binary.BigEndian.Uint16(g.Data4[0:2]),
		g.Data4[2:])
}

type TemplateEvent struct {
	Data   string
	Digest []byte
}

func PrepareMeasurements(events []Event) []TemplateEvent {
	ParseGPTEntries(events)
	templateEvents := make([]TemplateEvent, 0)
	for _, event := range events {
		if event.Index != 8 {
			continue
		}
		fmt.Printf("----Event %d----\n", event.Sequence)
		fmt.Printf("Type: %s\n", eventTypeNames[event.Typ])
		grubData := string(event.Data)
		if strings.HasPrefix(grubData, "grub_cmd ") {
			grubData = strings.TrimPrefix(grubData, "grub_cmd ")
		} else if strings.HasPrefix(string(event.Data), "grub_kernel_cmdline ") {
			grubData = strings.TrimPrefix(grubData, "grub_kernel_cmdline ")
			grubData = strings.TrimSuffix(grubData, "\x00")
		}
		imgAGuid := diskGuids[ImgA]
		imgBGuid := diskGuids[ImgB]
		imgAGuidStr := fmt.Sprintf("%s", &imgAGuid)
		imgBGuidStr := fmt.Sprintf("%s", &imgBGuid)
		grubData = strings.Replace(grubData, imgAGuidStr, "IMGGUID", -1)
		grubData = strings.Replace(grubData, imgBGuidStr, "IMGGUID", -1)
		grubData = strings.Replace(grubData, "hd0,gpt2", "IMGDEVID", -1)
		grubData = strings.Replace(grubData, "hd0,gpt3", "IMGDEVID", -1)
		grubData = strings.Replace(grubData, "hd0,gpt4", "CONFIGDEVID", -1)
		grubData = strings.Replace(grubData, "hd0", "CONFIGDISK", -1)
		h := sha256.New()
		h.Write([]byte(grubData))
		fmt.Printf("Data: %s\n", grubData)
		computedDigest := h.Sum(nil)
		fmt.Printf("Computed Hash: %x\n", computedDigest)
		tEvent := TemplateEvent{Data: grubData, Digest: computedDigest}
		templateEvents = append(templateEvents, tEvent)
		for _, digest := range event.Digests {
			if digest.Hash == crypto.SHA256 {
				fmt.Printf("Digest: %x\n", digest.Data)
			}
		}
	}
	return templateEvents
}

func ValidateEventLog(events []Event, pcrs map[int][]byte, templateEvents []TemplateEvent) error {
	//First validate that eventlog matches pcrs
	derivedPcrs := EventLogIterate(events)
	for i, digest := range pcrs {
		fmt.Printf("Comparing PCRS %x and %x\n", derivedPcrs[i], digest)
		if !reflect.DeepEqual(digest, derivedPcrs[i]) {
			return fmt.Errorf("PCR %d does not match, have %x but want %x",
				i, derivedPcrs[i], digest)
		}
	}

	//All good with PCRs, now get PCR8 events from events
	PCR8Events := PrepareMeasurements(events)
	for i, e := range PCR8Events {
		fmt.Printf("Comparing PCR 8 Events %s and %s\n", e.Data, templateEvents[i].Data)
		if !reflect.DeepEqual(e.Data, templateEvents[i].Data) {
			return fmt.Errorf("PCR8 event %s does not match",
				e.Data)
		}
	}
	return nil
}
