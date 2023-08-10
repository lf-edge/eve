package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"

	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
	"github.com/vishvananda/netlink"
)

const (
	logfileDir       = "/tmp/eve-bridge/"
	logfile          = logfileDir + "eve-bridge.log"
	niStatusFileDir  = "/run/k3s/eve-bridge/"

	eveKubeNamespace = "eve-kube-app"

	logMaxSize       = 100 // 100 Mbytes in size
	logMaxBackups    = 3   // old log files to retain
	logMaxAge        = 30  // days to retain old log files
)

// EveLocalConf represents the network tuning configuration.
type EveLocalConf struct {
	types.NetConf
	Port    string      `json:"port,omitempty"`
	NodeIP  string      `json:"nodeip,omitempty`
}

type EveClusterNIType uint32

const (
	ClusterNITypeNone EveClusterNIType = iota
	ClusterNIInternal
	ClusterNITypeLocal
	ClusterNITypeSwitch
)

type EVEClusterNIOp uint32

const (
	ClusterOPNone EVEClusterNIOp = iota
	ClusterOPAdd
	ClusterOPDel
)

type EveClusterInstStatus struct {
	ContainerID   string           `json:"containerID"`
	CNIOp         EVEClusterNIOp   `json:"cniOp"`

	K8Snamespace  string           `json:"k8sNamespace,omitempty"`
	BridgeConfig  string           `json:"bridgeConfig,omitempty"`
	NIType        EveClusterNIType `json:"niType,omitempty"`
	LogicalLabel  string           `json:"logicalLabel,omitempty"`

	BridgeName    string           `json:"bridgeName,omitempty"`
	BridgeMAC     string           `json:"bridgeMac,omitempty"`

	PodName       string           `json:"podName,omitempty"`
	PodNameSpace  string           `json:"podNamespace,omitempty"`
	PodIntfName   string           `json:"podIntfName,omitempty"`
	PodIntfMAC    string           `json:"podIntfMac,omitempty"`

	PodIntfPrefix net.IPNet        `json:"podIntfPrefix,omitempty"`
	PodIntfGW     net.IP           `json:"podIntfGw,omitempty"`

	VifName       string           `json:"vifName,omitempty"`
	VifMAC        string           `json:"vifMac,omitempty"`
}

var logFile *lumberjack.Logger
var cmdStr, containeridStr, nsStr, ifStr, argsStr string

func parseConf(data []byte, envArgs string) (*EveLocalConf, error) {
	conf := EveLocalConf{}
	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %v", err)
	}

	cmdStr = os.Getenv("CNI_COMMAND")
	containeridStr = os.Getenv("CNI_CONTAINERID")
	nsStr = os.Getenv("CNI_NETNS")
	ifStr = os.Getenv("CNI_IFNAME")
	argsStr = os.Getenv("CNI_ARGS")
	logStr := fmt.Sprintf("parseConf: cmd: %s, container-id: %s, ns: %s, ifname: %s, args: %s", cmdStr, containeridStr, nsStr, ifStr, argsStr)
	printLog(logStr)

	return &conf, nil
}

func printLog(logStr string) {
	log.Printf("%s", fmt.Sprintf("(%s) %s\n", time.Now().String(), logStr))
}

// copy from mults, pkg/netutils/netutils.go
func deleteDefaultGWResultRoutes(routes []interface{}, dstGW string) ([]interface{}, error) {
	for i, r := range routes {
		route, ok := r.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("wrong route format: %v", r)
		}
		_, ok = route["dst"]
		if ok {
			dst, ok := route["dst"].(string)
			if !ok {
				return nil, fmt.Errorf("wrong dst format: %v", route["dst"])
			}
			if dst == dstGW {
				routes = append(routes[:i], routes[i+1:]...)
			}
		}
	}
	return routes, nil
}

func addCustomRoute(routes []interface{}, newroute string) ([]interface{}, error) {
	myRoute := make(map[string]interface{})
	myRoute["dst"] = newroute
	routes = append(routes, myRoute)
	return routes, nil
}

func addClusterIPRoute(ifName string, gw net.IP, ippref string) error {
	if ippref == "" {
		return fmt.Errorf("no ip prefix %q", ifName)
	}
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	_, ipnet, err := net.ParseCIDR(ippref)
	if err != nil {
		return fmt.Errorf("failed to parse cidr error %v", err)
	}

	route := netlink.Route{
		Dst:        ipnet,
		LinkIndex:  link.Attrs().Index,
		Gw:         gw,
	}
	if err = netlink.RouteAddEcmp(&route); err != nil {
		return fmt.Errorf("failed to add route '%v via %v dev %v': %v", ipnet, gw, ifName, err)
	}
	logStr := fmt.Sprintf("addClusterIPRoute add route '%v via %v dev %v'", ipnet, gw, ifName)
	printLog(logStr)
	return nil
}

func isEveKubeApp(k8sns string) bool {
	if k8sns == eveKubeNamespace {
		return true
	}
	return false
}

func cmdAdd(args *skel.CmdArgs) error {
	logStr := fmt.Sprintf("cmdAdd: enter, stddata: %s", string(args.StdinData))
	printLog(logStr)
	eveLocalConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	logStr = fmt.Sprintf("cmdAdd: eveLocalConf: %+v", eveLocalConf)
	printLog(logStr)

	containerNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return err
	}
	logStr = fmt.Sprintf("cmdAdd: containerNS %v", containerNs)
	printLog(logStr)

	if err = validateArgs(args); err != nil {
		return err
	}

	// Parse previous result.
	if eveLocalConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	var namespace string
	n1 := strings.Split(nsStr, "/")
	n := len(n1)
	if n > 0 {
		namespace = n1[n - 1]
	}

	var podName, podMAC, k8sns string
	n2s := strings.Split(argsStr, ";")
	for _, n2 := range n2s {
		if strings.HasPrefix(n2, "K8S_POD_NAME=") {
			n2a := strings.Split(n2, "K8S_POD_NAME=")
			if len(n2a) == 2 {
				podName = n2a[1]
			}
		} else if strings.HasPrefix(n2, "MAC=") {
			n2b := strings.Split(n2, "MAC=")
			if len(n2b) == 2 {
				podMAC = n2b[1]
			}
		} else if strings.HasPrefix(n2, "K8S_POD_NAMESPACE=") {
			n2c := strings.Split(n2, "K8S_POD_NAMESPACE=")
			if len(n2c) == 2 {
				k8sns = n2c[1]
			}
		}
	}

	var bname, bmac, vname, vmac string
	var podprefix net.IPNet
	var podgw net.IP
	//var suppressDefRoute bool
	niType := ClusterNITypeSwitch
	if ifStr == "eth0" {
		niType = ClusterNIInternal
	}
	for imap, intf := range eveLocalConf.RawPrevResult {
		if imap == "routes" {
			data, err := json.Marshal(intf)
			//newroutes := []*types.Route{}
			//var gotDefRt bool
			if err == nil {
				routes := []*types.Route{}
				err := json.Unmarshal(data, &routes)
				if err != nil {
					continue
				}
				for a, b := range routes {
					logStr := fmt.Sprintf("=routes: %v, dst %v, gw %v", a, b.Dst, b.GW)
					printLog(logStr)
				}
			}
		} else if imap == "ips" {
			data, err := json.Marshal(intf)
			if err == nil {
				ips := []*current.IPConfig{}
				err := json.Unmarshal(data, &ips)
				if err != nil {
					continue
				}
				for a, b := range ips {
					podprefix = b.Address
					podgw = b.Gateway
					logStr := fmt.Sprintf("=ips: %v, intf %v, addr %v, gw %v", a, b.Interface, b.Address, b.Gateway)
					printLog(logStr)
				}
			}
		} else if imap == "interfaces" {
			data, err := json.Marshal(intf)
			if err == nil {
				intfs := []*current.Interface{}
				err := json.Unmarshal(data, &intfs)
				if err != nil {
					continue
				}
				for a, b := range intfs {
					if strings.HasPrefix(b.Name, "bn") {
						b2 := strings.Split(b.Name, "bn")
						if len(b2) == 2 {
							num, err := strconv.Atoi(b2[1])
							if err == nil && num < 100 {
								bname = b.Name
								bmac = b.Mac
								niType = ClusterNITypeLocal
							}
						}
					} else if strings.HasPrefix(b.Name, "veth") {
						vname = b.Name
						vmac = b.Mac
					}
					logStr := fmt.Sprintf("=interfaces: %v, name %v, mac %v, sb %v", a, b.Name, b.Mac, b.Sandbox)
					printLog(logStr)
				}
			}
		}
	}

	isEvePod := isEveKubeApp(k8sns)
	if niType == ClusterNIInternal {
		err = containerNs.Do(func(_ ns.NetNS) error {
			if !isEvePod { // install default route if not our pod
				err := addClusterIPRoute(args.IfName, podgw, "0.0.0.0/0")
				if err != nil {
					return err
				}
			} else {
				err := addClusterIPRoute(args.IfName, podgw, "10.43.0.0/16")
				if err != nil {
					return err
				}

				err = addClusterIPRoute(args.IfName, podgw, eveLocalConf.NodeIP)
				if err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			logStr := fmt.Sprintf("containerNS func error1 %v", err)
			printLog(logStr)
		}
	}

	if err := version.ParsePrevResult(&eveLocalConf.NetConf); err != nil {
		return err
	}

	niStatus := &EveClusterInstStatus{
		ContainerID:   containeridStr,
		CNIOp:         getOPtype(cmdStr),
		K8Snamespace:  k8sns,
		BridgeConfig:  eveLocalConf.Name,
		LogicalLabel:  eveLocalConf.Port,
		NIType:        niType,
		PodNameSpace:  namespace,
		PodName:       podName,
		PodIntfName:   ifStr,
		PodIntfMAC:    podMAC,
		BridgeName:    bname,
		BridgeMAC:     bmac,
		PodIntfPrefix: podprefix,
		PodIntfGW:     podgw,
		VifName:       vname,
		VifMAC:        vmac,
	}

	logStr = fmt.Sprintf("cmdAdd: before exit. ni Status: %+v", niStatus)
	printLog(logStr)

	if isEvePod && niType != ClusterNIInternal {
		writeStatus(niStatus)
	}
	return types.PrintResult(eveLocalConf.PrevResult, eveLocalConf.CNIVersion)
}

// cmdDel will restore NIC attributes to the original ones when called
func cmdDel(args *skel.CmdArgs) error {
	eveLocalConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}
	logStr := fmt.Sprintf("cmdDel: enter, stddata: %s, eveLocalConf %+v", string(args.StdinData), eveLocalConf)
	printLog(logStr)

	var k8sns string
	n2s := strings.Split(argsStr, ";")
	for _, n2 := range n2s {
		if strings.HasPrefix(n2, "K8S_POD_NAMESPACE=") {
			n2c := strings.Split(n2, "K8S_POD_NAMESPACE=")
			if len(n2c) == 2 {
				k8sns = n2c[1]
				break
			}
		}
	}
	isEvePod := isEveKubeApp(k8sns)

	if isEvePod {
		niStatus := &EveClusterInstStatus{
			ContainerID:   containeridStr,
			CNIOp:         getOPtype(cmdStr),
			BridgeConfig:  eveLocalConf.Name,
			LogicalLabel:  eveLocalConf.Port,
			PodIntfName:   ifStr,
		}

		delStatus(niStatus)
	}
	return nil
}

func getOPtype(cmdStr string) EVEClusterNIOp {
	if cmdStr == "ADD" {
		return ClusterOPAdd
	} else if cmdStr == "DEL" {
		return ClusterOPDel
	}
	return ClusterOPNone
}

func writeStatus(niStatus *EveClusterInstStatus) {
	if niStatus == nil {
		return
	}
	fname := niStatusFileDir + niStatus.ContainerID + "." + niStatus.PodIntfName + ".json"
	nifile, err := os.Create(fname)
	if err != nil {
		logStr := fmt.Sprintf("writeStatus: file create failed %v", err)
		printLog(logStr)
		return
	}
	defer nifile.Close()

	jstatus, err := json.MarshalIndent(niStatus, "", "  ")
	if err != nil {
		logStr := fmt.Sprintf("writeStatus: marshal failed %v", err)
		printLog(logStr)
		return
	}
	n, err := nifile.WriteString(string(jstatus))
	logStr := fmt.Sprintf("writeStatus: write %d bytes, %v", n, err)
	printLog(logStr)
}

func delStatus(niStatus *EveClusterInstStatus) {
	if niStatus == nil {
		return
	}
	fname := niStatusFileDir + niStatus.ContainerID + "." + niStatus.PodIntfName + ".json"
	if _, err := os.Stat(fname); err != nil {
		logStr := fmt.Sprintf("Status file %s stat error: %v", fname, err)
		printLog(logStr)
		return
	}

	if err := os.Remove(fname); err != nil {
		logStr := fmt.Sprintf("Status file %s remove error: %v", fname, err)
		printLog(logStr)
		return
	}
	logStr := fmt.Sprintf("Status file %s removed", fname)
	printLog(logStr)
}

func main() {
	if _, err := os.Stat(logfileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logfileDir, 0755); err != nil {
			return
		}
	}
	if _, err := os.Stat(niStatusFileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(niStatusFileDir, 0755); err != nil {
			return
		}
	}

	logFile = &lumberjack.Logger{
        Filename:   logfile,   // Path to the log file.
        MaxSize:    logMaxSize,        // Maximum size in megabytes before rotation.
        MaxBackups: logMaxBackups,     // Maximum number of old log files to retain.
        MaxAge:     logMaxAge,         // Maximum number of days to retain old log files.
        Compress:   true,              // Whether to compress rotated log files.
        LocalTime:  true,              // Use the local time zone for file names.
    }
	log.SetOutput(logFile)
	logStr := "eve-bridge main() Start"
	printLog(logStr)
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("eve-local"))
	logStr = "eve-bridge main() exit"
	printLog(logStr)
	logFile.Close()
}

func cmdCheck(args *skel.CmdArgs) error {
	logStr := fmt.Sprintf("cmdCheck: enter, stddata: %s", string(args.StdinData))
	printLog(logStr)
	eveLocalConf, err := parseConf(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Parse previous result.
	if eveLocalConf.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(&eveLocalConf.NetConf); err != nil {
		return err
	}

	_, err = current.NewResultFromResult(eveLocalConf.PrevResult)
	if err != nil {
		return err
	}

	return nil
}

func validateArgs(args *skel.CmdArgs) error {
	if strings.Contains(args.IfName, string(os.PathSeparator)) {
		return errors.New(fmt.Sprintf("Interface name (%s) contains an invalid character %s", args.IfName, string(os.PathSeparator)))
	}
	return nil
}
