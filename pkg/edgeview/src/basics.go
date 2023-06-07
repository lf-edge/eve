// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/shirou/gopsutil/host"
	"github.com/sirupsen/logrus"
)

const (
	colorRED    = "\033[1;31m%s\033[0m"
	colorBLUE   = "\033[1;34m%s\033[0m"
	colorCYAN   = "\033[1;36m%s\033[0m"
	colorGREEN  = "\033[0;32m%s\033[0m"
	colorYELLOW = "\033[0;93m%s\033[0m"
	colorPURPLE = "\033[1;95m%s\033[0m"
	colorRESET  = "\033[0m"
)

var (
	netopts       []string
	pubsubopts    []string
	pubsubpersist []string
	pubsublarge   []string
	sysopts       []string
	logdirectory  []string
	basics        basicItems
)

type basicItems struct {
	uuid       string // device UUID
	server     string // /config/server
	release    string // EVE release
	partition  string // device partition
	proxy      string // proxy ip:port
	evUseProxy bool   // if proxy, and edgeview uses it
	evendpoint string // public IP informed by dispatcher
}

// all the supported options
func initOpts() {
	netopts = []string{
		"acl",
		"addhost",
		"app",
		"arp",
		"connectivity",
		"flow",
		"if",
		"mdns",
		"nslookup",
		"showcerts",
		"ping",
		"route",
		"socket",
		"speed",
		"tcp",
		"tcpdump",
		"trace",
		"url",
		"wireless"}

	pubsubopts = []string{
		"baseosmgr",
		"domainmgr",
		"downloader",
		"edgeview",
		"global",
		"loguploader",
		"newlogd",
		"nim",
		"nodeagent",
		"tpmmgr",
		"vaultmgr",
		"volumemgr",
		"watcher",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter",
		"zfsmanager"}

	pubsubpersist = []string{
		"nim",
		"tpmmgr",
		"volumemgr",
		"zedagent",
		"zedclient",
		"zedmanager",
		"zedrouter"}

	pubsublarge = []string{
		"zedagent",
		"zedmanager"}

	sysopts = []string{
		"app",
		"configitem",
		"cat",
		"cp",
		"datastore",
		"dmesg",
		"download",
		"du",
		"hw",
		"lastreboot",
		"ls",
		"model",
		"newlog",
		"pci",
		"ps",
		"cipher",
		"usb",
		"tar",
		"techsupport",
		"top",
		"volume",
		"pprof",
	}

	logdirectory = []string{
		"/persist/newlog/keepSentQueue/",
		"/persist/newlog/devUpload/",
		"/persist/newlog/appUpload/",
		"/persist/newlog/failedUpload/",
	}
}

// checkOpts -
// a pre-defined sets of 'network', 'system', 'pub' commands are supported, the command options can be
// multiple and separated by ',', this function to verify each of the command is valid and supported
// against the lists.
func checkOpts(opt string, optslice []string) ([]string, error) {
	opts := strings.Split(opt, ",")
	for _, o := range opts {
		ok := false
		if strings.Contains(o, "/") {
			opt1 := strings.Split(o, "/")
			ok = isDefinedOpt(opt1[0], optslice)
		} else {
			ok = isDefinedOpt(o, optslice)
		}
		if !ok {
			return []string{}, fmt.Errorf("options available: %v", optslice)
		}
	}
	return opts, nil
}

func isDefinedOpt(value string, optslice []string) bool {
	for _, opt := range optslice {
		if opt == value {
			return true
		}
	}
	return false
}

// get url and path from JWT token string
func getAddrFromJWT(token string, isServer bool, instID int) (string, string, error) {
	var addrport, path string
	tparts := strings.Split(token, ".")
	if len(tparts) != 3 {
		return addrport, path, fmt.Errorf("no ip:port or invalid JWT")
	}

	if instID > 0 {
		if instID > types.EdgeviewMaxInstNum {
			return addrport, path, fmt.Errorf("JWT inst number incorrect")
		}
		edgeviewInstID = instID
	}

	data, err := base64.RawURLEncoding.DecodeString(tparts[1])
	if err != nil {
		return addrport, path, err
	}

	var jdata types.EvjwtInfo
	err = json.Unmarshal(data, &jdata)
	if err != nil {
		return addrport, path, err
	}

	var uuidStr string
	if isServer {
		retbytes, err := os.ReadFile("/persist/status/uuid")
		if err == nil {
			uuidStr = strings.TrimSuffix(string(retbytes), "\n")
		}
	}

	if jdata.Exp == 0 || jdata.Dep == "" {
		return addrport, path, fmt.Errorf("read JWT data failed")
	}
	if uuidStr != "" && jdata.Sub != uuidStr {
		return addrport, path, fmt.Errorf("uuid does not match JWT jti")
	}

	now := time.Now()
	nowSec := uint64(now.Unix())
	if nowSec > jdata.Exp {
		return addrport, path, fmt.Errorf("JWT expired %d sec ago", nowSec-jdata.Exp)
	}

	if jdata.Num > 1 && instID < 1 {
		if runOnServer {
			return addrport, path, fmt.Errorf("Edgeview is in multi-instance mode, '-inst 1-%d' needs to be specified", jdata.Num)
		} else {
			warnStr := fmt.Sprintf("Edgeview is in multi-instance mode, use '-inst 1-%d', try '-inst 1' here", jdata.Num)
			fmt.Printf("%s\n", getColorStr(warnStr, colorCYAN))
			edgeviewInstID = 1
		}
	} else if jdata.Num == 1 && instID > 0 {
		if runOnServer {
			return addrport, path, fmt.Errorf("Edgeview is not in multi-instance mode, no need to specify inst-ID")
		} else {
			fmt.Printf("%s\n", getColorStr("Edgeview is not in multi-instance mode, instance ignored here", colorCYAN))
			edgeviewInstID = 0
		}
	}

	// remove the https:// prefix if exists
	jdataDep := strings.TrimPrefix(jdata.Dep, "https://")
	jdataDep = strings.TrimPrefix(jdataDep, "http://")
	if strings.Contains(jdataDep, "/") {
		urls := strings.SplitN(jdataDep, "/", 2)
		if len(urls) != 2 {
			return addrport, path, fmt.Errorf("JWT url invalid")
		}
		addrport = urls[0]
		path = "/" + urls[1]
	} else {
		addrport = jdataDep
	}

	evStatus.ExpireOn = jdata.Exp
	evStatus.StartedOn = now
	encryptVarInit(jdata)

	return addrport, path, nil
}

func checkClientIPMsg(msg string) bool {
	if strings.HasPrefix(msg, clientIPMsg) {
		msgs := strings.SplitN(msg, clientIPMsg, 2)
		if len(msgs) == 2 {
			addrPort := strings.Split(msgs[1], ":")
			if net.ParseIP(addrPort[0]) == nil {
				log.Errorf("received invalid IP %v", msg)
				return false
			}
			if len(addrPort) == 2 {
				num, err := strconv.Atoi(addrPort[1])
				if err != nil || num < 1024 || num > 65535 {
					log.Errorf("received invalid IP %v", msg)
					return false
				}
			} else if len(addrPort) > 2 {
				log.Errorf("received invalid IP %v", msg)
				return false
			}
			basics.evendpoint = msgs[1]
			return true
		}
	}
	return false
}

func evLogger(deb bool) *logrus.Logger {
	formatter := logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
	}
	logger := logrus.New()
	logger.SetFormatter(&formatter)
	log = base.NewSourceLogObject(logger, agentName, os.Getpid())
	if deb {
		logger.SetLevel(logrus.DebugLevel)
	}
	return logger
}

func getBasics() {
	if runOnServer {
		if _, err := os.Stat("/config"); err != nil {
			return
		}
	}

	ips := []string{}
	for _, i := range allUPIntfIPv4() {
		if strings.HasPrefix(i.intfName, "bn") {
			continue
		}
		ips = append(ips, i.ipAddr)
	}
	addStr := ""
	if basics.proxy != "" && basics.evUseProxy {
		addStr = " (proxy " + basics.proxy + ")"
	}
	if basics.evendpoint != "" {
		fmt.Printf("Device IPs: %v; Endpoint IP %s%s\n", ips, basics.evendpoint, addStr)
	} else {
		fmt.Printf("Device IPs: %v%s\n", ips, addStr)
	}

	if basics.uuid == "" {
		retbytes, err := os.ReadFile("/persist/status/uuid")
		if err == nil {
			basics.uuid = string(retbytes)
		}
	}
	fmt.Printf("  UUID: %s", basics.uuid)

	devInfo := getDevInfo()
	if devInfo.DeviceName != "" {
		fmt.Printf("  Device: %s, Enterprise: %s\n", devInfo.DeviceName, devInfo.EnterpriseName)
	}

	if basics.server == "" {
		retbytes, err := os.ReadFile("/config/server")
		if err == nil {
			server := string(retbytes)
			basics.server = strings.TrimSuffix(server, "\n")
		}
	}

	if basics.server != "" {
		var printed bool
		conts := strings.Split(basics.server, "zedcloud.")
		if len(conts) == 2 {
			cont2s := strings.Split(conts[1], ".zededa.net")
			if len(cont2s) == 2 { // color highlight the cluster name string
				cluster := cont2s[0]
				colorCluster := getColorStr(cluster, colorYELLOW)
				controller := strings.Replace(basics.server, cluster, colorCluster, 1)
				fmt.Printf("  Controller: %s", controller)
				printed = true
			}
		}
		if !printed {
			fmt.Printf("  Controller: %s", basics.server)
		}
	}

	if basics.release == "" {
		retbytes, err := os.ReadFile("/run/eve-release")
		if err == nil {
			basics.release = string(retbytes)
		}
	}

	if basics.partition == "" {
		retbytes, err := os.ReadFile("/run/eve.id")
		if err == nil {
			basics.partition = string(retbytes)
		}
	}

	fmt.Printf("  EVE-OS release %s, %s", basics.release, basics.partition)
	fmt.Printf("  Edge-View Ver: %s, JWT expires at %v\n",
		edgeViewVersion, time.Unix(int64(evStatus.ExpireOn), 0).Format(time.RFC3339))
	hinfo, err := host.Info()
	if err == nil {
		loc, _ := time.LoadLocation("UTC")
		fmt.Printf("  %v(%v), uptime %d (sec) = %d days",
			time.Now().In(loc).Format(time.RFC3339), loc, hinfo.Uptime, hinfo.Uptime/(3600*24))
	}
	fmt.Println()
	fmt.Println()
	closePipe(true)
}

// dynamically install package for uncommon options
func addPackage(pathName, pkgName string) error {
	prog := "apk"
	_, err := os.Stat(pathName)
	if err != nil {
		if os.IsNotExist(err) {
			args := []string{"add", pkgName}
			_, err = runCmdInFunction(prog, args)
			if err != nil {
				fmt.Printf("%v\n", err)
				return err
			}
		} else {
			return err
		}
	}
	return nil
}

func runCmd(prog string, args []string, isPrint bool) (string, error) {
	var retStr string
	var retBytes []byte
	var err error

	retBytes, err = runCmdInFunction(prog, args)
	if err != nil {
		if !strings.HasSuffix(err.Error(), "status 1") {
			fmt.Printf("error: %v\n", err)
		}
	} else {
		retStr = string(retBytes)
		if isPrint {
			fmt.Println(retStr)
			closePipe(true)
		}
	}
	return retStr, err
}

func runCmdInFunction(prog string, args []string) ([]byte, error) {
	cmd := exec.Command(prog, args...)
	stdout, err := cmd.Output()
	if err != nil {
		log.Errorf("exec.Command error: %v", err)
		return nil, err
	} else {
		return stdout, nil
	}
}

func runPipeCmds(prog1 string, arg1 []string, prog2 string, arg2 []string) (string, error) {
	closePipe(false)

	var c1, c2 *exec.Cmd
	c1 = exec.Command(prog1, arg1...)
	c2 = exec.Command(prog2, arg2...)

	r, w := io.Pipe()
	c1.Stdout = w
	c2.Stdin = r

	var b2 bytes.Buffer
	c2.Stdout = &b2

	c1.Start()
	c2.Start()
	go func() {
		defer w.Close()
		c1.Wait()
	}()
	c2.Wait()
	out, err := io.ReadAll(&b2)
	if err != nil {
		reOpenPipe(true)
		return "", err
	}
	reOpenPipe(true)
	return string(out), nil
}

func printColor(msg, color string) {
	fmt.Printf(color, msg)
	fmt.Println("")
}

func getColorStr(msg, color string) string {
	return fmt.Sprintf(color, msg)
}

func printTitle(msg, color string, sendnow bool) {
	printColor(msg, color)
	if sendnow {
		closePipe(true)
	}
}

func getJSONFileID(path string) string {
	strs := strings.Split(path, "/")
	n := len(strs)
	if n > 0 {
		filename := strs[n-1]
		fileid := strings.Split(filename, ".json")
		if len(fileid) > 0 {
			return fileid[0]
		}
	}
	return ""
}

func getTokenHashString(token string) []byte {
	if edgeviewInstID > 0 {
		token = token + "." + strconv.Itoa(edgeviewInstID)
	}
	h := sha256.New()
	_, err := h.Write([]byte(token))
	if err != nil {
		fmt.Printf("hash write error: %v\n", err)
	}
	hash16 := h.Sum(nil)[:16]
	return []byte(base64.RawURLEncoding.EncodeToString(hash16))
}

// in the format of yyyyMMDDhhmmss to use as part of the file name
func getFileTimeStr(t1 time.Time) string {
	t := t1.UTC()
	return fmt.Sprintf("%d%02d%02d%02d%02d%02d", t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func listJSONFiles(path string) ([]string, error) {
	files, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}

	var jfiles []string
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			dir := path
			if !strings.HasSuffix(path, "/") {
				dir = dir + "/"
			}
			jfiles = append(jfiles, dir+f.Name())
		}
	}
	return jfiles, nil
}

func findAllFileInfo(path string) ([]os.FileInfo, error) {
	var finfos []os.FileInfo
	err1 := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			info.Name()
			finfos = append(finfos, info)
		}
		return nil
	})
	if err1 != nil {
		return nil, err1
	}
	return finfos, nil
}

func listRecursiveFiles(path, pattern string) ([]string, error) {
	var jfiles []string
	err1 := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(info.Name(), pattern) {
			jfiles = append(jfiles, path)
		}
		return nil
	})
	if err1 != nil {
		return nil, err1
	}
	return jfiles, nil
}

var helpStr = `eve-edgeview [ -token <session-token> ] [ -inst <instance-id> ] <query command>
 query options:
`

func printHelp(opt string) {
	if opt == "" {
		fmt.Println(helpStr)
		fmt.Printf("  %v\n", netopts)
		fmt.Printf("  %v\n", sysopts)
		fmt.Printf("  log/search-pattern [ -time <start_time>-<end_time> -json -type <app|dev> -line <num> ]\n")
		fmt.Printf("  pub/ %v\n", pubsubopts)
		fmt.Printf("\n  For more detail help on EdgeView commands, see https://wiki.lfedge.org/display/EVE/EdgeView+Commands\n\n")
	} else {
		fmt.Printf("\n")
		switch opt {
		// network
		case "acl":
			helpOn("acl[/<filter>]", "to display all filters of running and configured ACL")
			helpExample("acl", "display all filters of ACL", true)
			helpExample("acl/nat", "display in table nat of ACL", false)
		case "addhost":
			helpOn("addhost/host-name/host-IP", "to add a host entry in EdgeView container's /etc/hosts file")
		case "app":
			helpOn("app[/app-string]", "to display all the app or one specific app")
			helpExample("app", "display all apps in brief", true)
			helpExample("app/iot", "display a specific app, which app name has substring of iot in more detail", false)
		case "arp":
			helpOn("arp[/filter]", "to display all the arp entry or with filter matching")
			helpExample("arp", "display all arp entries", true)
			helpExample("arp/192.168", "display all arp entries contain 192.168 string", false)
		case "connectivity":
			helpOn("connectivity", "display the port config list with index")
		case "flow":
			helpOn("flow[/<some pattern>]", "display ip flow information in the kernel search pattern")
			helpExample("flow/sport=53", "display all the ip flow matches source port of 53", true)
			helpExample("flow/10.1.0.2", "display all the ip flow matches ip address of 10.1.0.2", false)
		case "if":
			helpOn("if[/intf-name]", "display interface related information briefly")
			helpExample("if/eth0", "display interface eth0 related information", true)
		case "mdns":
			helpOn("mdns[/intf-name][/service]", "display zeroconfig related information")
			helpExample("mdns/eth0", "display mDNS for default service 'workstation' on interface 'eth0'", true)
			helpExample("mdns/bn1/https", "display mDNS for service 'https' on bridge 'bn1'", false)
			helpExample("mdns", "display mDNS for default service 'workstation' on all UP interafces", false)
		case "nslookup":
			helpOn("nslookup[/<ip or name>]", "display domain name and dns server information")
			helpExample("nslookup/www.amazon.com", "display DNS information on www.amazon.com", true)
			helpExample("nslookup/8.8.8.8", "display DNS information on address 8.8.8.8", false)
		case "showcerts":
			helpOn("showcerts[/<url>][/proxy-addr:proxy-port]", "display TLS connection certificates of server side")
			helpExample("showcerts/zedcloud.local.zededa.net", "display TLS certificates from the controller", true)
			helpExample("showcerts/zedcloud.local.zededa.net/10.10.1.128:3128", "display controller TLS certificates through a proxy server", false)
		case "ping":
			helpOn("ping[/<ip or name>]", "ping to 8.8.8.8 from all the UP interfaces or ping a specific address")
			helpExample("ping", "ping to 8.8.8.8 from each source IP address of the interfaces", true)
			helpExample("ping/192.168.1.1", "ping the address of 192.168.1.1", false)
		case "route":
			helpOn("route", "display all the ip rule and their ip table entries")
		case "socket":
			helpOn("socket", "display all the ipv4 litening socket ports and established ports")
		case "speed":
			helpOn("speed[/intf-name]", "run speed test and report the download and upload speed")
			helpExample("speed/wlan0", "run speed test on interface wlan0", true)
		case "tcp":
			helpOn("tcp/ip-address:port[/ip-address:port...][/proxy[@ip-addr]]", "tcp connection to the ip addresses for services, local mapping ports 9001 and above")
			helpExample("tcp/192.168.1.1:8080", "points your browser to the locally listening port and http browsing 192.168.1.1:8080", true)
			helpExample("tcp/10.1.0.2:80/10.1.0.2:8081", "points your browser to the locally listening ports and http browsing remote 10.1.0.2 both 80 and 8081 ports", false)
			helpExample("tcp/proxy/localhost:5903", "https proxy to locally listening ports and vnc viewer to #3 port on device", false)
			helpExample("tcp/proxy@10.1.2.3", "https proxy and specify the address of DNS name server for URL lookup", false)
		case "tcpdump":
			helpOn("tcpdump/intf-name/[options]", "tcpdump on the interface, can specify duration with -time, default is 60 sec")
			helpExample("tcpdump/eth0/", "run tcpdump on eth0 with default 60 seconds or maximum of 100 entries", true)
			helpExample("tcpdump/eth0/'port 443' -time 10", "run tcpdump on eth0 and port 443 with 10 seconds", false)
		case "trace":
			helpOn("trace[/<ip or name>]", "traceroute to www.google.com and zedcloud server, or to specified ip or name, 10 hops limit")
			helpExample("trace", "traceroute to www.google.com and to zedcloud server", true)
			helpExample("trace/www.microsoft.com", "run traceroute to www.microsoft.com", false)
		case "url":
			helpOn("url", "display url metrics for zedclient, zedagent, downloader and loguploader")
		case "wireless":
			helpOn("wireless", "display the iwconfig wlan0 info and wpa_supplicant.conf content")
		// system
		case "configitem":
			helpOn("configitem", "display the device configitem settings, highlight the non-default values")
		case "cp":
			helpOn("cp/<path>", "copy file from the device to locally mounted directory by specify the path")
			helpExample("cp//config/device.cert.pem", "copy the /config/device.cert.pem file to local directory", true)
			helpExample("cp//persist/newlog/keepSentQueue/dev.log.1630451424116.gz", "copy file with path to local directory", false)
		case "cat":
			helpOn("cat/<path to filename>", "to display the content of a file")
			helpExample("cat//config/device.cert.pem", "display the /config/device.cert.pem file content", true)
			helpExample("cat/<path> -line <num>", "display only <num> of lines, like 'head' if <num> is positive, like 'tail' if the <num> is negative", false)
		case "datastore":
			helpOn("datastore", "display the device current datastore: EQDN, type, cipher information")
		case "pprof":
			helpOn("pprof", "pprof/on to turn on pprof; pprof/off to turn off again")
		case "dmesg":
			helpOn("dmesg", "display the device current dmesg information")
		case "download":
			helpOn("download", "display the download config and status during downloading operation and url stats since reboot")
		case "du":
			helpOn("du", "display linux 'du' in disk usage of a directory")
			helpExample("du//persist/vault", "get the total disk usage of files under that directory", true)
		case "hw":
			helpOn("hw", "display the hardware from lshw information in json format")
		case "lastreboot":
			helpOn("lastreboot", "display the last reboot reasons and stack if the information is saved")
		case "ls":
			helpOn("ls/<path to filenames>", "to display the file/directory information")
			helpExample("ls//config/device.cert.pem", "display the /config/device.cert.pem file info", true)
			helpExample("ls//config/\"device*\"", "display all the files with prefix 'device' in /config", false)
		case "model":
			helpOn("model", "display the hardware model information in json format")
		case "newlog":
			helpOn("newlog", "display the newlog statistics and file information in each of the newlog directory and disk usage")
		case "pci":
			helpOn("pci", "display the lspci information on device")
		case "ps":
			helpOn("ps/<string>", "display the process status information on matching string")
			helpExample("ps/containerd", "display the processes with name of containerd", true)
		case "top":
			helpOn("top", "display linux 'top' in one batch")
			helpExample("top -line 20", "display the first 20 lines of linux 'top' output", true)
		case "cipher":
			helpOn("cipher", "display cipher information on datastore, device and controller certificates, etc.")
		case "usb":
			helpOn("usb", "display the lsusb information on device")
		case "tar":
			helpOn("tar/<path to directory>", "to generate a tarfile of the directory")
			helpExample("tar//persist/agentdebug", "download the tarfile persist.agentdebug.<time>.tar of that directory", true)
		case "techsupport":
			helpOn("techsupport", "show tech-support, run various edgeview commands with output downloaded in a compressed file")
		case "volume":
			helpOn("volume", "display the app volume and content tree information for each app")
		// log
		case "log":
			helpOn("log/<search string> [-time <start>-<end>] [-json] [-type <app|dev>]", "display log with search-string, default is now to 30 mins ago")
			helpExample("log/panic -time 0.2-2.5", "display log contains 'panic', from 0.2 to 0.5 hours ago", true)
			helpExample("log/Clock -type app", "display previous 30 minutes log contains 'Clock' in app log", false)
			helpExample("log/certificate -time 2021-08-15T23:15:29Z-2021-08-15T22:45:00Z -json",
				"display log during the specified time in RFC3339 format which contains 'certificate' in json format", false)
			helpExample("log/copy-logfiles -time 2022-02-15T22:25:00Z-2022-02-15T22:40:00Z",
				"'copy-logfiles' is reserved usage, to download all logfiles in the specified time duration, maximum time frame is 30 minutes", false)
		default:
			printHelp("")
		}
	}
}

func helpOn(str1, str2 string) {
	fmt.Printf(" %s  -  %s\n", str1, str2)
}

func helpExample(str1, str2 string, printEG bool) {
	egStr := "    "
	if printEG {
		egStr = "e.g."
	}
	fmt.Printf("  %s %s  -- %s\n", egStr, str1, str2)
}
