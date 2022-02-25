package nettb

import (
	"context"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Logger interface {
	Functionf(format string, args ...interface{})
}

// NetDev reads /proc/net/dev file and returns network devices listed there
func NetDev() ([]string, error) {
	content, err := ioutil.ReadFile("/proc/net/dev")
	if err != nil {
		return nil, err
	}
	procnetdev := strings.Split(string(content), "\n")
	if len(procnetdev) <= 2 {
		return nil, fmt.Errorf("/proc/net/dev does not contain any interfaces")
	}

	return processNetDev(procnetdev), nil
}

func processNetDev(lines []string) []string {
	var ans []string
	for _, iface := range lines[2:] { // first two lines are headerlines
		idx := strings.Index(iface, ":")
		if idx > -1 {
			ans = append(ans, iface[:idx])
		}
	}
	return ans
}

func GetPciToIfNameMapByTimeout(timeout time.Duration) (map[string]string, error) {
	toCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c := asyncPciToIfNameMap(toCtx)
	for {
		select {
		case ans := <-c:
			return ans, nil
		case <-toCtx.Done():
			return nil, fmt.Errorf("GetPciToIfNameMapByTimeout reached timeout %v", timeout)
		}
	}
}

func asyncPciToIfNameMap(ctx context.Context) chan map[string]string {
	c := make(chan (map[string]string))
	go func() {
		select {
		default:
			time.Sleep(1 * time.Second)
			ifNameMap, err := PciToIfNameMap()
			if err == nil && ifNameMap != nil {
				c <- ifNameMap
				return
			}
		case <-ctx.Done():
			return
		}
	}()
	return c
}

// PciToIfNameMap returns map of PCI addresses for every device in /proc/net/dev
func PciToIfNameMap() (map[string]string, error) {
	netDevIfaces, err := NetDev()
	if err != nil {
		return nil, err
	}

	const sysClassNetPath = "/sys/class/net"

	info, err := ioutil.ReadDir(sysClassNetPath)
	if err != nil {
		return nil, err
	}
	var sysClassNetDevices []string
	for _, f := range info {
		sysClassNetDevices = append(sysClassNetDevices, f.Name())
	}

	ifaces := intersection(netDevIfaces, sysClassNetDevices)

	return getPciAddrsForDevices(sysClassNetPath, ifaces), nil
}

func intersection(s1, s2 []string) (inter []string) {
	hash := make(map[string]bool)
	for _, e := range s1 {
		hash[strings.TrimSpace(e)] = true
	}
	for _, e := range s2 {
		if hash[strings.TrimSpace(e)] {
			inter = append(inter, strings.TrimSpace(e))
		}
	}
	return inter
}

func getPciAddrsForDevices(root string, devices []string) map[string]string {
	pciBdfRe := regexp.MustCompile("[0-9a-f]{4}:[0-9a-f]{2,4}:[0-9a-f]{2}\\.[0-9a-f]$")
	res := make(map[string]string)
	for _, d := range devices {
		path, err := filepath.EvalSymlinks(filepath.Join(root, d, "/device"))
		if err != nil {
			continue
		}
		pci_addr := pciBdfRe.FindString(path)
		if pci_addr == "" {
			continue
		}
		res[pci_addr] = d
	}
	return res
}
