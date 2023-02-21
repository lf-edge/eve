// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package zedrouter

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func init() {
	logger = logrus.StandardLogger()
	log = base.NewSourceLogObject(logger, "zedrouter", 1234)
}

type dnsmasqConfigletParams struct {
	ctx          *zedrouterContext
	bridgeName   string
	bridgeIPAddr net.IP
	netstatus    *types.NetworkInstanceStatus
	hostsDir     string
	ipsetHosts   []string
	uplink       string
	dnsServers   []net.IP
	ntpServers   []net.IP
}

func exampleDnsmasqConfigletParams() dnsmasqConfigletParams {
	var dcp dnsmasqConfigletParams

	dcp.bridgeName = "br0"
	dcp.bridgeIPAddr = net.IP{10, 0, 0, 1}

	var netstatus types.NetworkInstanceStatus
	netstatus.DhcpRange.Start = net.IP{10, 0, 0, 2}
	netstatus.DhcpRange.End = net.IP{10, 0, 0, 123}
	dcp.netstatus = &netstatus

	dcp.hostsDir = "/etc/hosts.d"
	dcp.ipsetHosts = []string{"zededa.com", "example.com"}

	dcp.uplink = "up0"

	dcp.dnsServers = []net.IP{{1, 1, 1, 1}, {141, 1, 1, 1}, {208, 67, 220, 220}}
	dcp.ntpServers = []net.IP{{94, 130, 35, 4}, {94, 16, 114, 254}}

	return dcp
}

func runCreateDnsmasqConfiglet(dcp dnsmasqConfigletParams) string {
	var buf bytes.Buffer

	createDnsmasqConfigletToWriter(&buf, dcp.ctx, dcp.bridgeName, dcp.bridgeIPAddr,
		dcp.netstatus, dcp.hostsDir, dcp.ipsetHosts, dcp.uplink, dcp.dnsServers,
		dcp.ntpServers)

	return buf.String()
}

type dnsmasqReturn struct {
	output  string
	err     error
	exitErr *exec.ExitError
}

func runDnsmasq(args []string) (chan<- struct{}, <-chan dnsmasqReturn) {
	var err error

	endChan := make(chan struct{})
	dnsmasqOutputChan := make(chan dnsmasqReturn)
	var bufOut bytes.Buffer

	cmd := exec.Command(args[0], args[1:]...) // TODO: make args to string...
	cmd.Stdout = &bufOut
	cmd.Stderr = &bufOut
	go func() {
		leasesDir := "/run/zedrouter/dnsmasq.leases"
		os.MkdirAll(leasesDir, 0750)
		defer os.RemoveAll(leasesDir)

		err = cmd.Start()
		if err != nil {
			panic(fmt.Sprintf("could not run dnsmasq: %+v", err))
		}

		<-endChan
		err = cmd.Process.Kill()
		if err != nil {
			panic(err)
		}
		err = cmd.Wait() // ignoring the exit status code / signal

		var dr dnsmasqReturn
		dr.output = bufOut.String()
		dr.err = err
		switch e := dr.err.(type) {
		case *exec.ExitError:
			dr.exitErr = e
		}
		dnsmasqOutputChan <- dr
	}()

	return endChan, dnsmasqOutputChan
}

func requestDhcp(mac net.HardwareAddr, vethPeerName string, timeout time.Duration) *net.IP {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	dhcpOptions := []nclient4.ClientOpt{
		nclient4.WithRetry(4),
		nclient4.WithHWAddr(mac),
		nclient4.WithTimeout(timeout),
	}

	if testing.Verbose() {
		dhcpOptions = append(dhcpOptions, nclient4.WithSummaryLogger())
	}

	client, err := nclient4.New(vethPeerName, dhcpOptions...)
	if err != nil {
		panic(err)
	}
	defer client.Close()

	lease, err := client.Request(ctx)
	if err != nil {
		//panic(err)
		return nil
	}

	if lease != nil && lease.Offer != nil {
		return &lease.Offer.YourIPAddr
	} else {
		return nil
	}
}

func incByteArray(arr []byte) {
	changed := false
	for i := len(arr) - 1; i >= 0; i-- {
		// byte is just an alias for uint8 (https://go.dev/ref/spec#Numeric_types)
		if arr[i] == math.MaxUint8 {
			arr[i] = 0
			continue
		}
		arr[i]++
		changed = true
		break
	}

	if !changed {
		for i := range arr {
			arr[i] = 0
		}
	}
}

func multiRequestDhcp(macs []net.HardwareAddr, vethPeerName string, timeout time.Duration) mac2Ip {
	var m2ip mac2Ip
	var m2ipMutex sync.Mutex

	var wg sync.WaitGroup
	for _, mac := range macs {
		wg.Add(1)
		go func(mac net.HardwareAddr) {
			ip := requestDhcp(mac, vethPeerName, timeout)
			m2ipMutex.Lock()
			if ip != nil {
				m2ip.add(mac, *ip)
			}
			m2ipMutex.Unlock()
			wg.Done()
		}(mac)
	}

	wg.Wait()

	return m2ip
}

func TestIncByteArray(t *testing.T) {
	t.Parallel()

	v := []byte{1, 2}
	incByteArray(v)

	if v[0] != 1 || v[1] != 3 {
		t.Fatalf("incByteArray failed: %+v", v)
	}

	v = []byte{255, 255}
	incByteArray(v)

	if v[0] != 0 || v[1] != 0 {
		t.Fatalf("incByteArray failed: %+v", v)
	}

	v = []byte{250, 255}
	incByteArray(v)
	if v[0] != 251 || v[1] != 0 {
		t.Fatalf("incByteArray failed: %+v", v)
	}
}

type dhcpNetworkEnv struct {
	vethName          string
	vethPeerName      string
	bridgeName        string
	pathToDnsmasqConf string
}

// create different interfaces if running tests in parallel
var networkInterfacesID uint32

func createDhcpNetworkEnv(bridgeAddr *netlink.Addr) (dhcpNetworkEnv, bool) {
	var dnEnv dhcpNetworkEnv

	networkInterfaceID := atomic.AddUint32(&networkInterfacesID, 1)

	dnEnv.vethName = fmt.Sprintf("veth-%d", networkInterfaceID)
	dnEnv.vethPeerName = fmt.Sprintf("vpeer-%d", networkInterfaceID)
	dnEnv.bridgeName = fmt.Sprintf("br-%d", networkInterfaceID)

	la := netlink.NewLinkAttrs()
	la.Name = dnEnv.bridgeName
	dnsmasqBridge := &netlink.Bridge{LinkAttrs: la}
	err := netlink.LinkAdd(dnsmasqBridge)
	if err != nil && err.Error() == "operation not permitted" {
		return dnEnv, false
	} else if err != nil {
		panic(err)
	}
	err = netlink.AddrAdd(dnsmasqBridge, bridgeAddr)
	if err != nil {
		panic(err)
	}

	// add veth device and connect to bridge
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: dnEnv.vethName,
			MTU:  dnsmasqBridge.Attrs().MTU,
		},
		PeerName: dnEnv.vethPeerName,
	}
	err = netlink.LinkAdd(veth)
	if err != nil {
		panic(err)
	}

	vethPeerLink, err := netlink.LinkByName(dnEnv.vethPeerName)
	if err != nil {
		panic(err)
	}
	vethLink, err := netlink.LinkByName(dnEnv.vethName)
	if err != nil {
		panic(err)
	}
	err = netlink.LinkSetMaster(vethLink, dnsmasqBridge)
	if err != nil {
		panic(err)
	}

	for _, ifname := range []netlink.Link{dnsmasqBridge, vethPeerLink, vethLink} {
		err := netlink.LinkSetUp(ifname)
		if err != nil {
			panic(fmt.Sprintf("Setting up %s failed: %+v", ifname, err))
		}
	}

	return dnEnv, true
}

func (dnEnv *dhcpNetworkEnv) Stop() {
	for _, ifname := range []string{dnEnv.vethName, dnEnv.bridgeName} {
		link, err := netlink.LinkByName(ifname)
		if err != nil {
			panic(fmt.Sprintf("LinkByName of %s: %+v", ifname, err))
		}
		netlink.LinkDel(link)
	}
}

type mac2Ip struct {
	macs []net.HardwareAddr
	ips  []net.IP
}

func compareMac2Ip(a, b mac2Ip) bool {
	if len(a.macs) != len(b.macs) || len(a.ips) != len(b.ips) || len(a.ips) != len(a.macs) {
		return false
	}

	mac2ipToString := func(mac net.HardwareAddr, ip net.IP) string {
		return fmt.Sprintf("%s->%s", mac, ip)
	}

	aMap := make(map[string]struct{})

	for i := 0; i < len(a.macs); i++ {
		mac := a.macs[i]
		ip := a.ips[i]

		aMap[mac2ipToString(mac, ip)] = struct{}{}
	}

	for i := 0; i < len(b.macs); i++ {
		mac := b.macs[i]
		ip := b.ips[i]

		_, ok := aMap[mac2ipToString(mac, ip)]
		if !ok {
			return false
		}
	}

	return true
}

func (m2ip *mac2Ip) add(mac net.HardwareAddr, ip net.IP) {
	m2ip.macs = append(m2ip.macs, mac)
	m2ip.ips = append(m2ip.ips, ip)

	if len(m2ip.macs) != len(m2ip.ips) {
		panic("length wrong")
	}
}

func createMac2Ip(count int, startIPAddr net.IP) mac2Ip {
	var ret mac2Ip

	ip := make(net.IP, len(startIPAddr))
	copy(ip, startIPAddr)
	startMac := net.HardwareAddr{0x00, 0xC, 0xA, 0xB, 0x1, 0xE}
	for i := 0; i < count; i++ {
		mac := make(net.HardwareAddr, len(startMac))
		copy(mac, startMac)
		ip := make(net.IP, len(startIPAddr))
		copy(ip, startIPAddr)
		ret.add(mac, ip)
		incByteArray(startIPAddr)
		incByteArray(startMac)
	}

	return ret
}

func createDhcpHostsDirFile(path string, mi mac2Ip) {
	dhcpHostsDirFile, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer dhcpHostsDirFile.Close()

	for i := 0; i < len(mi.ips); i++ {
		mac := mi.macs[i]
		ip := mi.ips[i]
		line := fmt.Sprintf("%s,%s\n", mac, ip)
		dhcpHostsDirFile.WriteString(line)
	}
}

func TestRunDnsmasq(t *testing.T) {
	if testing.Short() {
		t.Skipf("Running dnsmasq skipped as this is rather a component test")
	}

	t.Parallel()
	dhcpTimeout := 30 * time.Second

	f, err := os.CreateTemp("", "dnsmasq.conf-")
	if err != nil {
		panic(err)
	}

	dcp := exampleDnsmasqConfigletParams()
	dcp.netstatus.DhcpRange.Start = net.IP{10, 0, 0, 2}
	dcp.netstatus.DhcpRange.End = net.IP{10, 0, 0, 4}

	bridgeAddr, err := netlink.ParseAddr(fmt.Sprintf("%s/24", dcp.bridgeIPAddr))
	if err != nil {
		panic(err)
	}
	dnEnv, ok := createDhcpNetworkEnv(bridgeAddr)
	if !ok {
		t.Skipf("Could not create bridge device, probably not enough permissions")
	}
	defer dnEnv.Stop()

	dcp.bridgeName = dnEnv.bridgeName
	conf := runCreateDnsmasqConfiglet(dcp)
	pathToConf := f.Name()
	f.WriteString(conf)
	f.Close()
	defer os.Remove(pathToConf)

	dhcpHostsDir := filepath.Join("/", "run", "zedrouter", fmt.Sprintf("dhcp-hosts.%s", dnEnv.bridgeName))
	os.MkdirAll(dhcpHostsDir, 0750)
	defer os.RemoveAll(dhcpHostsDir)

	countClients := 5

	m2ip := createMac2Ip(countClients, dcp.netstatus.DhcpRange.Start)
	hostsFilePath := filepath.Join(dhcpHostsDir, "test.hosts")
	createDhcpHostsDirFile(hostsFilePath, m2ip)

	dhcpEndChan, dnsmasqOutputChan := runDnsmasq([]string{
		"dnsmasq",
		"-d",
		"-C",
		pathToConf},
	)

	unregisteredClientIP := requestDhcp(net.HardwareAddr{0x00, 0x09, 0x45, 0x5d, 0x8b, 0x08}, dnEnv.vethPeerName, dhcpTimeout)
	if unregisteredClientIP != nil {
		t.Fatalf("unknown clients should not receive IP address from dnsmasq, but got %+v", unregisteredClientIP)
	}

	dhcpM2Ip := multiRequestDhcp(m2ip.macs, dnEnv.vethPeerName, dhcpTimeout)

	dhcpEndChan <- struct{}{}

	dnsmasqReturn := <-dnsmasqOutputChan

	// ignoring if dnsmasq got killed as we killed it
	if dnsmasqReturn.exitErr != nil && dnsmasqReturn.exitErr.Exited() && !dnsmasqReturn.exitErr.Success() {
		t.Logf("dnsmasq failed: %+v\noutput: %s", dnsmasqReturn.err, dnsmasqReturn.output)
	}

	if !compareMac2Ip(m2ip, dhcpM2Ip) {
		hostsFileContent, err := os.ReadFile(hostsFilePath)
		if err != nil {
			t.Logf("could not even read hosts file %s: %+v", hostsFilePath, err)
		}
		t.Fatalf("requested ips/macs(len %d):\n%+v\ndiffer from provided ips/macs(len %d):\n%+v\nhostsFile:\n%s", len(dhcpM2Ip.ips), dhcpM2Ip, len(m2ip.ips), m2ip, hostsFileContent)
	}
}

func TestCreateDnsmasqConfigletWithoutDhcpRangeEnd(t *testing.T) {
	t.Parallel()

	dcp := exampleDnsmasqConfigletParams()

	dcp.netstatus.DhcpRange.End = nil

	config := runCreateDnsmasqConfiglet(dcp)

	dhcpRangeRex := "(?m)^dhcp-range=10.0.0.2,static,255.255.255.0,60m$"
	ok, err := regexp.MatchString(dhcpRangeRex, config)
	if err != nil {
		panic(err)
	}
	if !ok {
		t.Fatalf("expected to match '%s', but got '%s'", dhcpRangeRex, config)
	}

}

func TestCreateDnsmasqConfigletWithDhcpRangeEnd(t *testing.T) {
	t.Parallel()

	dcp := exampleDnsmasqConfigletParams()
	config := runCreateDnsmasqConfiglet(dcp)

	configExpected := `
# Automatically generated by zedrouter
except-interface=lo
bind-interfaces
quiet-dhcp
quiet-dhcp6
no-hosts
no-ping
bogus-priv
neg-ttl=10
dhcp-ttl=600
dhcp-leasefile=/run/zedrouter/dnsmasq.leases/br0
server=1.1.1.1@up0
server=141.1.1.1@up0
server=208.67.220.220@up0
no-resolv
ipset=/zededa.com/ipv4.zededa.com,ipv6.zededa.com
ipset=/example.com/ipv4.example.com,ipv6.example.com
pid-file=/run/dnsmasq.br0.pid
interface=br0
listen-address=10.0.0.1
hostsdir=/etc/hosts.d
dhcp-hostsdir=/run/zedrouter/dhcp-hosts.br0
dhcp-option=option:ntp-server,94.130.35.4,94.16.114.254
dhcp-option=option:router
dhcp-option=option:dns-server
dhcp-range=10.0.0.2,10.0.0.123,255.255.255.0,60m
`
	if configExpected != config {
		t.Fatalf("expected '%s', but got '%s'", configExpected, config)
	}
}

func TestRunDnsmasqInvalidDhcpRange(t *testing.T) {
	t.Parallel()

	line, err := dhcpv4RangeConfig(nil, nil)
	if err != nil {
		panic(err)
	}

	if line != "" {
		t.Fatalf("dhcp-range is '%s', expected ''", line)
	}

	line, err = dhcpv4RangeConfig(net.IP{10, 0, 0, 5}, net.IP{10, 0, 0, 3})
	if err == nil {
		t.Fatalf("expected dhcp range to fail, but got %s", line)
	}
}
