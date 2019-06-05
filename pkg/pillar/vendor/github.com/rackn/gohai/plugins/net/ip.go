package net

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	SIOCETHTOOL        = 0x8946
	CMD_GSET           = 1
	CMD_GLINKSETTINGS  = 0x4c
	GSET_SIZE          = 44
	GLINKSETTINGS_SIZE = 48
)

var endian binary.ByteOrder

func init() {
	var i int = 0x1
	const INT_SIZE int = int(unsafe.Sizeof(0))
	bs := (*[INT_SIZE]byte)(unsafe.Pointer(&i))
	if bs[0] == 0 {
		endian = binary.BigEndian
	} else {
		endian = binary.LittleEndian
	}
}

type ifReq struct {
	ifName [16]byte
	data   uintptr
}

func (i *ifReq) Name() string {
	return string(i.ifName[:])
}

func (i *ifReq) SetName(name string) {
	copy(i.ifName[:], name)
	i.ifName[15] = 0
}

func (i *ifReq) ioctl(cmd uint32, buf []byte) error {
	endian.PutUint32(buf[:4], cmd)
	bufHdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	i.data = bufHdr.Data
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	_, _, errCode := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		SIOCETHTOOL,
		uintptr(unsafe.Pointer(i)))
	if errCode != 0 {
		return syscall.Errno(errCode)
	}
	return nil
}

type ModeBit struct {
	Name, Phy       string
	Feature, Duplex bool
}

func (m ModeBit) String() string {
	if m.Feature {
		return m.Name
	}
	res := fmt.Sprintf("%s base %s", m.Name, m.Phy)
	if m.Duplex {
		return res + " Full"
	}
	return res + " Half"
}

var arpHW = map[int64]string{
	0:      "netrom",
	1:      "ethernet",
	2:      "experimental ethernet",
	3:      "ax25",
	4:      "pronet",
	5:      "chaos",
	6:      "ieee802",
	7:      "arcnet",
	8:      "appletalk",
	15:     "dlci",
	19:     "atm",
	23:     "metricom",
	24:     "ieee1394",
	27:     "eui-64",
	32:     "infiniband",
	256:    "slip",
	257:    "cslip",
	258:    "slip6",
	259:    "cslip6",
	260:    "reserved",
	264:    "adapt",
	270:    "rose",
	271:    "x25",
	272:    "hwx25",
	280:    "can",
	512:    "ppp",
	513:    "hdlc",
	516:    "labp",
	517:    "ddcmp",
	518:    "rawhdlc",
	519:    "rawip",
	768:    "ipip",
	769:    "ip6ip6",
	770:    "frad",
	771:    "skip",
	772:    "loopback",
	773:    "localtalk",
	774:    "fddi",
	775:    "bif",
	776:    "sit",
	777:    "ipddp",
	778:    "ipgre",
	779:    "pimreg",
	780:    "hippi",
	781:    "ash",
	782:    "econet",
	783:    "irda",
	784:    "fcpp",
	785:    "fcal",
	786:    "fcpl",
	787:    "fcfabric",
	800:    "ieee802_tr",
	801:    "ieee80211",
	802:    "ieee80211_prism",
	803:    "ieee80211_radiotap",
	804:    "ieee802154",
	805:    "ieee802154_monitor",
	820:    "phonet",
	821:    "phonet_pipe",
	822:    "caif",
	823:    "ip6gre",
	824:    "netlink",
	825:    "6lowpan",
	826:    "vsockmon",
	0xfffe: "none",
	0xffff: "void",
}

var modeBits = [][8]ModeBit{
	{
		{"10", "T", false, false},
		{"10", "T", false, true},
		{"100", "T", false, false},
		{"100", "T", false, true},
		{"1000", "T", false, false},
		{"1000", "T", false, true},
		{"Autoneg", "", true, false},
		{"TP", "", true, false},
	},
	{
		{"AUI", "", true, false},
		{"MII", "", true, false},
		{"FIBRE", "", true, false},
		{"BNC", "", true, false},
		{"10000", "T", false, true},
		{"Pause", "", true, false},
		{"Asym_Pause", "", true, false},
		{"2500", "X", false, true},
	},
	{
		{"Backplane", "", true, false},
		{"1000", "KX", false, true},
		{"10000", "KX4", false, true},
		{"10000", "KR", false, true},
		{"10000", "R_FEC", false, true},
		{"20000", "MLD2", false, true},
		{"20000", "KR2", false, true},
		{"40000", "KR4", false, true},
	}, {
		{"40000", "CR4", false, true},
		{"40000", "SR4", false, true},
		{"40000", "LR4", false, true},
		{"56000", "KR4", false, true},
		{"56000", "CR4", false, true},
		{"56000", "SR4", false, true},
		{"56000", "LR4", false, true},
		{"25000", "CR", false, true},
	}, {
		{"25000", "KR", false, true},
		{"25000", "SR", false, true},
		{"50000", "CR2", false, true},
		{"50000", "KR2", false, true},
		{"100000", "KR4", false, true},
		{"100000", "SR4", false, true},
		{"100000", "CR4", false, true},
		{"100000", "LR4_ER4", false, true},
	}, {
		{"50000", "SR2", false, true},
		{"1000", "X", false, true},
		{"10000", "CR", false, true},
		{"10000", "SR", false, true},
		{"10000", "LR", false, true},
		{"10000", "LRM", false, true},
		{"10000", "ER", false, true},
		{"2500", "T", false, true},
	}, {
		{"5000", "T", false, true},
	},
}

type Flags net.Flags

func (f Flags) String() string {
	return net.Flags(f).String()
}

func (f Flags) MarshalText() ([]byte, error) {
	return []byte(f.String()), nil
}

type HardwareAddr net.HardwareAddr

func (h HardwareAddr) String() string {
	return net.HardwareAddr(h).String()
}

func (h HardwareAddr) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

type IPNet net.IPNet

func (n *IPNet) String() string {
	return (*net.IPNet)(n).String()
}

func (n *IPNet) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

type Interface struct {
	Name            string
	StableName      string
	Model           string
	Driver          string
	Vendor          string
	MTU             int
	Flags           Flags
	HardwareAddr    HardwareAddr
	Addrs           []*IPNet
	Supported       []ModeBit
	Advertised      []ModeBit
	PeerAdvertised  []ModeBit
	Speed           uint32
	Duplex          bool
	Autonegotiation bool
	Sys             struct {
		IsPhysical bool
		BusAddress string
		IfIndex    int64
		IfLink     int64
		OperState  string
		Type       string
		IsBridge   bool
		Bridge     struct {
			Members []string
			Master  string
		}
		IsVlan bool
		VLAN   struct {
			Id     int64
			Master string
		}
		IsBond bool
		Bond   struct {
			Mode      string
			Members   []string
			Master    string
			LinkState string
		}
	}
}

func toModeBits(buf []byte) []ModeBit {
	res := []ModeBit{}
	for segment, bits := range buf {
		if segment >= len(modeBits) {
			break
		}
		for i, modeBit := range modeBits[segment] {
			if bits&(1<<uint(i)) > 0 {
				res = append(res, modeBit)
			}
		}
	}
	return res
}

/* buf layout for GSET:
0..3: cmd
4..7: supported features
8..11: advertised features
12..13: low bits of speed
14: duplex
15: port in use
16: MDIO phy address
17: transceiver to use
18: autonegotiation
19: MDIO support
20..23: max tx packets before an interrupt
24..27: max rx packets before an interrupt
28..29: high bits of speed
30: tp mdix
31: reserved
32..35: partner advertised features
36..43: reserved
*/
func (i *Interface) fillGset(buf []byte) error {
	speedLo := endian.Uint16(buf[12:14])
	speedHi := endian.Uint16(buf[28:30])
	i.Speed = (uint32(speedHi) << 16) + uint32(speedLo)
	i.Duplex = buf[14] != 0
	i.Autonegotiation = buf[18] != 0
	i.Supported = toModeBits(buf[4:8])
	i.Advertised = toModeBits(buf[8:12])
	i.PeerAdvertised = toModeBits(buf[32:36])
	return nil
}

/* buf layout for GLINKSETTINGS:
0..3: cmd
4..7: speed
8: duplex
9: port
10: phy address
11: autonegotiation
12: MDIO support
13: eth tp mdix
14: eth tp mdix control
15: number of 32 bit words to be used for the
    supported features, advertised features, and peer advertised features bits
16..47
48: supported features, advertized features, peer advertised features
*/

func (i *Interface) fillGlink(buf []byte) error {
	i.Speed = endian.Uint32(buf[4:8])
	i.Duplex = buf[8] != 0
	i.Autonegotiation = buf[11] != 0
	b := int(buf[15]) << 2
	s := 48
	a := 48 + b
	p := a + b
	i.Supported = toModeBits(buf[s : s+b])
	i.Advertised = toModeBits(buf[a : a+b])
	i.PeerAdvertised = toModeBits(buf[p : p+b])
	return nil
}

func (i *Interface) fillUdev() error {
	cmd := exec.Command("udevadm", "info", "-q", "all", "-p", "/sys/class/net/"+i.Name)
	buf := &bytes.Buffer{}
	cmd.Stdout = buf
	if err := cmd.Run(); err != nil {
		return err
	}
	stableNameOrder := []string{"E: ID_NET_NAME_ONBOARD", "E: ID_NET_NAME_SLOT", "E: ID_NET_NAME_PATH"}
	stableNames := map[string]string{}
	sc := bufio.NewScanner(buf)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "E: ID_MODEL_FROM_DATABASE":
			i.Model = parts[1]
		case "E: ID_NET_DRIVER":
			i.Driver = parts[1]
		case "E: ID_VENDOR_FROM_DATABASE":
			i.Vendor = parts[1]
		case "E: ID_NET_NAME_ONBOARD", "E: ID_NET_NAME_SLOT", "E: ID_NET_NAME_PATH":
			stableNames[parts[0]] = parts[1]
		}
	}
	for _, n := range stableNameOrder {
		if val, ok := stableNames[n]; ok {
			i.StableName = val
			break
		}
	}
	return nil
}

func (i *Interface) sysPath(p string) string {
	return path.Join("/sys/class/net", i.Name, p)
}

func (i *Interface) sysString(p string) string {
	buf, err := ioutil.ReadFile(i.sysPath(p))
	if err == nil {
		return strings.TrimSpace(string(buf))
	}
	return ""
}

func (i *Interface) sysInt(p string) int64 {
	res, _ := strconv.ParseInt(i.sysString(p), 0, 64)
	return res
}
func (i *Interface) sysDir(p string) []string {
	res := []string{}
	f, err := os.Open(i.sysPath(p))
	if err != nil {
		return res
	}
	defer f.Close()
	ents, err := f.Readdirnames(0)
	if err != nil {
		for _, ent := range ents {
			if ent == "." || ent == ".." {
				continue
			}
			res = append(res, ent)
		}
	}
	return res
}

func (i *Interface) sysLink(p string) string {
	l, _ := os.Readlink(i.sysPath(p))
	return l
}

func (i *Interface) fillSys() error {
	link := i.sysLink("")
	link = strings.TrimPrefix(link, "../../devices/")
	i.Sys.BusAddress = strings.TrimSuffix(link, "/net/"+i.Name)
	i.Sys.IsPhysical = !strings.HasPrefix(i.Sys.BusAddress, "virtual/")
	i.Sys.IfIndex = i.sysInt("ifindex")
	i.Sys.IfLink = i.sysInt("iflink")
	i.Sys.OperState = i.sysString("operstate")
	i.Sys.Type = arpHW[i.sysInt("type")]
	i.Sys.Bridge.Members = []string{}
	i.Sys.Bond.Members = []string{}
	if dp := i.sysDir("brport"); dp != nil && len(dp) < 0 {
		i.Sys.IsBridge = true
		i.Sys.Bridge.Master = path.Base(i.sysLink("brport/bridge"))
	}
	if i.sysString("bridge/bridge_id") != "" {
		i.Sys.IsBridge = true
	}
	if dp := i.sysDir("brif"); dp != nil && len(dp) < 0 {
		i.Sys.Bridge.Members = dp
	}
	if sl := i.sysString("bonding/slaves"); sl != "" {
		i.Sys.IsBond = true
		i.Sys.Bond.Members = strings.Split(sl, " ")
	}
	if sm := i.sysString("bonding/mode"); sm != "" {
		i.Sys.IsBond = true
		i.Sys.Bond.Mode = strings.Split(sm, " ")[0]
	}
	if dp := i.sysString("bonding_slave/state"); dp != "" {
		i.Sys.IsBond = true
		i.Sys.Bond.LinkState = dp
		i.Sys.Bond.Master = path.Base(i.sysLink("master"))
	}
	if vlan, err := os.Open("/proc/net/vlan/config"); err == nil {
		defer vlan.Close()
		sc := bufio.NewScanner(vlan)
		for sc.Scan() {
			parts := strings.Split(sc.Text(), "|")
			if strings.TrimSpace(parts[0]) == i.Name {
				i.Sys.IsVlan = true
				i.Sys.VLAN.Id, _ = strconv.ParseInt(strings.TrimSpace(parts[1]), 0, 64)
				i.Sys.VLAN.Master = strings.TrimSpace(parts[2])
				break
			}
		}
	}
	return nil
}

func (i *Interface) Fill() error {
	if err := i.fillUdev(); err != nil {
		return err
	}
	if err := i.fillSys(); err != nil {
		return err
	}
	// First, try GLINKSETTINGS
	buf := make([]byte, 4096)
	req := &ifReq{}
	req.SetName(i.Name)
	err := req.ioctl(CMD_GLINKSETTINGS, buf)
	if err == nil {
		// We support GLINKSETTINGS, figure out how much space is needed for
		// additional bits and get the real data.
		additionalSize := int8(buf[15])
		if additionalSize < 0 {
			additionalSize = -additionalSize
			buf[15] = byte(additionalSize)
		}
		if err := req.ioctl(CMD_GLINKSETTINGS, buf); err != nil {
			return err
		}
		return i.fillGlink(buf)
	}
	if err := req.ioctl(CMD_GSET, buf); err != nil {
		return err
	}
	return i.fillGset(buf)
}

type Info struct {
	Interfaces    []Interface
	HardwareAddrs map[string]string
	Addrs         map[string]string
}

func (i *Info) Class() string {
	return "Networking"
}

func Gather() (*Info, error) {
	res := &Info{}
	baseifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	res.Interfaces = make([]Interface, len(baseifs))
	res.HardwareAddrs = map[string]string{}
	res.Addrs = map[string]string{}
	for i, intf := range baseifs {
		iface := Interface{
			Name:           intf.Name,
			HardwareAddr:   HardwareAddr(intf.HardwareAddr),
			MTU:            intf.MTU,
			Flags:          Flags(intf.Flags),
			Supported:      []ModeBit{},
			Advertised:     []ModeBit{},
			PeerAdvertised: []ModeBit{},
		}
		if iface.HardwareAddr != nil && len(iface.HardwareAddr) > 0 {
			res.HardwareAddrs[iface.HardwareAddr.String()] = iface.Name
		}
		addrs, err := intf.Addrs()
		if err != nil {
			return nil, err
		}
		iface.Addrs = []*IPNet{}
		for i := range addrs {
			addr, ok := addrs[i].(*net.IPNet)
			if ok {
				res.Addrs[addr.String()] = iface.Name
				iface.Addrs = append(iface.Addrs, (*IPNet)(addr))
			}
		}
		iface.Fill()
		res.Interfaces[i] = iface
	}
	return res, nil
}
