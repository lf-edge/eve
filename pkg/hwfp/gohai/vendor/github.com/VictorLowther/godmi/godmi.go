/*
* godmi.go
* DMI SMBIOS information
*
* Chapman Ou <ochapman.cn@gmail.com>
*
 */
package godmi

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const OUT_OF_SPEC = "<OUT OF SPEC>"

type SMBIOSStructureType byte

const (
	SMBIOSStructureTypeBIOS SMBIOSStructureType = iota
	SMBIOSStructureTypeSystem
	SMBIOSStructureTypeBaseBoard
	SMBIOSStructureTypeChassis
	SMBIOSStructureTypeProcessor
	SMBIOSStructureTypeMemoryController
	SMBIOSStructureTypeMemoryModule
	SMBIOSStructureTypeCache
	SMBIOSStructureTypePortConnector
	SMBIOSStructureTypeSystemSlots
	SMBIOSStructureTypeOnBoardDevices
	SMBIOSStructureTypeOEMStrings
	SMBIOSStructureTypeSystemConfigurationOptions
	SMBIOSStructureTypeBIOSLanguage
	SMBIOSStructureTypeGroupAssociations
	SMBIOSStructureTypeSystemEventLog
	SMBIOSStructureTypePhysicalMemoryArray
	SMBIOSStructureTypeMemoryDevice
	SMBIOSStructureType32_bitMemoryError
	SMBIOSStructureTypeMemoryArrayMappedAddress
	SMBIOSStructureTypeMemoryDeviceMappedAddress
	SMBIOSStructureTypeBuilt_inPointingDevice
	SMBIOSStructureTypePortableBattery
	SMBIOSStructureTypeSystemReset
	SMBIOSStructureTypeHardwareSecurity
	SMBIOSStructureTypeSystemPowerControls
	SMBIOSStructureTypeVoltageProbe
	SMBIOSStructureTypeCoolingDevice
	SMBIOSStructureTypeTemperatureProbe
	SMBIOSStructureTypeElectricalCurrentProbe
	SMBIOSStructureTypeOut_of_bandRemoteAccess
	SMBIOSStructureTypeBootIntegrityServices
	SMBIOSStructureTypeSystemBoot
	SMBIOSStructureType64_bitMemoryError
	SMBIOSStructureTypeManagementDevice
	SMBIOSStructureTypeManagementDeviceComponent
	SMBIOSStructureTypeManagementDeviceThresholdData
	SMBIOSStructureTypeMemoryChannel
	SMBIOSStructureTypeIPMIDevice
	SMBIOSStructureTypePowerSupply
	SMBIOSStructureTypeAdditionalInformation
	SMBIOSStructureTypeOnBoardDevicesExtendedInformation
	SMBIOSStructureTypeManagementControllerHostInterface                     /*42*/
	SMBIOSStructureTypeInactive                          SMBIOSStructureType = 126
	SMBIOSStructureTypeEndOfTable                        SMBIOSStructureType = 127
)

func (b SMBIOSStructureType) String() string {
	types := [...]string{
		"BIOS", /* 0 */
		"System",
		"Base Board",
		"Chassis",
		"Processor",
		"Memory Controller",
		"Memory Module",
		"Cache",
		"Port Connector",
		"System Slots",
		"On Board Devices",
		"OEM Strings",
		"System Configuration Options",
		"BIOS Language",
		"Group Associations",
		"System Event Log",
		"Physical Memory Array",
		"Memory Device",
		"32-bit Memory Error",
		"Memory Array Mapped Address",
		"Memory Device Mapped Address",
		"Built-in Pointing Device",
		"Portable Battery",
		"System Reset",
		"Hardware Security",
		"System Power Controls",
		"Voltage Probe",
		"Cooling Device",
		"Temperature Probe",
		"Electrical Current Probe",
		"Out-of-band Remote Access",
		"Boot Integrity Services",
		"System Boot",
		"64-bit Memory Error",
		"Management Device",
		"Management Device Component",
		"Management Device Threshold Data",
		"Memory Channel",
		"IPMI Device",
		"Power Supply",
		"Additional Information",
		"Onboard Device",
		"Management Controller Host Interface", /* 42 */
	}

	if b > 42 {
		return "unspported type:" + strconv.Itoa(int(b))
	}
	return types[b]
}

type SMBIOSStructureHandle uint16

type infoCommon struct {
	smType SMBIOSStructureType
	length byte
	handle SMBIOSStructureHandle
}

type entryPoint struct {
	Anchor        []byte //4
	Checksum      byte
	Length        byte
	MajorVersion  byte
	MinorVersion  byte
	MaxSize       uint16
	Revision      byte
	FormattedArea []byte // 5
	InterAnchor   []byte // 5
	InterChecksum byte
	TableLength   uint16
	TableAddress  uint32
	NumberOfSM    uint16
	BCDRevision   byte
}

type dmiHeader struct {
	infoCommon
	data      []byte
	strFields []string
}

/*
 * Attempt to find the DMI data.
 * First, look for /sys files.  This appears to work for linux kernel with /sys enabled.
 *   Return the filename of the quick DMI data blob.
 * Second, check for EFI address in the systab for efi.  If present, return the
 *   memory descriptor and no quick look file.
 * Third, scan memory for _SM_.
 */
func getEntryData() (data []byte, file string, err error) {
	// return /sys file if could be used.
	file = ""

	// Check for dmi in /sys
	data, err = ioutil.ReadFile("/sys/firmware/dmi/tables/smbios_entry_point")
	if err == nil {
		data, err = anchor(data)
		if err == nil {
			file = "/sys/firmware/dmi/tables/DMI"
			return
		}
	}

	// Check for efi
	data, err = ioutil.ReadFile("/sys/firmware/efi/systab")
	if err != nil {
		data, err = ioutil.ReadFile("/proc/efi/systab")
	}
	// we have a efi systab - look for address
	if err == nil {
		sdata := string(data)
		lines := strings.Split(sdata, "\n")

		for _, line := range lines {
			parts := strings.Split(line, "=")
			if len(parts) != 2 {
				continue
			}

			if parts[0] == "SMBIOS" {
				offset, err2 := strconv.ParseUint(parts[1], 0, 32)
				if err2 != nil {
					continue
				}
				data, err = getMem(uint32(offset), 0x20)
				if err == nil {
					data, err = anchor(data)
					if err == nil {
						return
					}
				}
			}
		}
		return nil, "", fmt.Errorf("EFI enabled, but table not found\n")
	}

	// Last ditch hope
	data, err = getMem(0xF0000, 0x10000)
	if err == nil {
		data, err = anchor(data)
	}
	return
}

func newEntryPoint() (eps *entryPoint, file string, err error) {
	eps = new(entryPoint)

	data, file, err := getEntryData()
	if err != nil {
		return
	}
	eps.Anchor = data[:0x04]
	eps.Checksum = data[0x04]
	eps.Length = data[0x05]
	eps.MajorVersion = data[0x06]
	eps.MinorVersion = data[0x07]
	eps.MaxSize = u16(data[0x08:0x0A])
	eps.Revision = data[0x0A]
	eps.FormattedArea = data[0x0B:0x0F]
	eps.InterAnchor = data[0x10:0x15]
	eps.TableLength = u16(data[0x16:0x18])
	eps.TableAddress = u32(data[0x18:0x1C])
	eps.NumberOfSM = u16(data[0x1C:0x1E])
	eps.BCDRevision = data[0x1E]
	return
}

func (e entryPoint) StructureTableMem() ([]byte, error) {
	return getMem(e.TableAddress, uint32(e.TableLength))
}

func newdmiHeader(d []byte) *dmiHeader {
	if len(d) < 0x04 {
		return nil
	}
	h := dmiHeader{
		infoCommon: infoCommon{
			smType: SMBIOSStructureType(d[0x00]),
			length: d[1],
			handle: SMBIOSStructureHandle(u16(d[0x02:0x04])),
		},
		data: d,
	}
	h.setStringFields()
	return &h
}

func (h dmiHeader) Next() *dmiHeader {
	index := h.getStructTableEndIndex()

	if index == -1 {
		return nil
	}
	return newdmiHeader(h.data[index+2:])
}

func (h dmiHeader) getStructTableEndIndex() int {
	de := []byte{0, 0}
	next := h.data[h.length:]
	endIdx := bytes.Index(next, de)
	if endIdx == -1 {
		return -1
	}
	return int(h.length) + endIdx
}

func (h dmiHeader) decode() error {
	t := h.smType
	newfn, err := getTypeFunc(t)
	if err != nil {
		return err
	}
	newfn(h)
	return nil
}

func (h *dmiHeader) setStringFields() {
	index := h.getStructTableEndIndex()
	if index == -1 {
		return
	}
	fieldData := h.data[h.length:index]
	bs := bytes.Split(fieldData, []byte{0})
	for _, v := range bs {
		h.strFields = append(h.strFields, string(v))
	}
}

func (h dmiHeader) FieldString(strIndex int) string {
	if strIndex == 0 {
		return ""
	}
	if strIndex > len(h.strFields) {
		return fmt.Sprintf("FieldString ### ERROR:strFields Len:%d, strIndex:%d", len(h.strFields), strIndex)
	}
	return h.strFields[strIndex-1]
}

func (e entryPoint) StructureTable(file string) error {
	var err error
	var tmem []byte
	if file == "" {
		tmem, err = e.StructureTableMem()
	} else {
		tmem, err = ioutil.ReadFile(file)
	}
	if err != nil {
		return err
	}
	for hd := newdmiHeader(tmem); hd != nil; hd = hd.Next() {
		err := hd.decode()
		if err != nil {
			//fmt.Println("info: ", err)
			continue
		}
	}
	return nil
}

type dmiTyper interface {
	String() string
}

type newFunction func(d dmiHeader) dmiTyper

type typeFunc map[SMBIOSStructureType]newFunction

var g_typeFunc = make(typeFunc)

var g_lock sync.Mutex

func addTypeFunc(t SMBIOSStructureType, f newFunction) {
	g_lock.Lock()
	defer g_lock.Unlock()
	g_typeFunc[t] = f
}

func getTypeFunc(t SMBIOSStructureType) (fn newFunction, err error) {
	fn, ok := g_typeFunc[t]
	if !ok {
		return fn, fmt.Errorf("type %d have no NewFunction", int(t))
	}
	return fn, nil
}

func Init() error {
	eps, file, err := newEntryPoint()
	if err != nil {
		return err
	}
	return eps.StructureTable(file)
}

func getMem(base uint32, length uint32) (mem []byte, err error) {
	file, err := os.Open("/dev/mem")
	if err != nil {
		return
	}
	defer file.Close()
	fd := file.Fd()
	mmoffset := base % uint32(os.Getpagesize())
	mm, err := syscall.Mmap(int(fd), int64(base-mmoffset), int(mmoffset+length), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return
	}
	mem = make([]byte, length)
	copy(mem, mm[mmoffset:])
	err = syscall.Munmap(mm)
	if err != nil {
		return
	}
	return
}

func anchor(mem []byte) ([]byte, error) {
	anchor := []byte{'_', 'S', 'M', '_'}
	i := bytes.Index(mem, anchor)
	if i == -1 {
		return nil, fmt.Errorf("find anchor error!")
	}
	return mem[i:], nil
}

func version(mem []byte) string {
	ver := strconv.Itoa(int(mem[0x06])) + "." + strconv.Itoa(int(mem[0x07]))
	return ver
}
