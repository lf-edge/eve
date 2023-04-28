package netdump

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/lf-edge/eve/libs/nettrace"
)

const (
	// Directory where network dumps are persistently stored for later analysis.
	netdumpDir = "/persist/netdump"

	// The layout should be such that string ordering corresponds to the time ordering.
	// Avoid characters which are not suitable for filenames (across all OSes).
	netdumpTimestampFormat = "2006-01-02T15-04-05"

	// Netdumps are wrapped inside Tar GZ Files.
	netdumpExtension = ".tgz"
)

// NetDumper publishes (writes to /persist/netdump) tar.gz archives containing network
// diagnostic information for post-mortem analysis of device connectivity issues.
type NetDumper struct {
	// MaxDumpsPerTopic : maximum number of archives with network diagnostic information
	// (aka network dumps) that can be persistent at the same time for a given topic.
	// NetDumper will remove the oldest network dump of a given topic before publishing
	// a new one that would otherwise exceed this limit.
	// By default (zero value), there is no limit.
	// Can be changed between calls to Publish.
	MaxDumpsPerTopic int
}

// TracedNetRequest : trace and potentially one or more packet captures obtained
// during a request targeted at a remote endpoint (i.e. carried over the network).
type TracedNetRequest struct {
	// RequestName : name of the executed request that had its network operations traced.
	// It is used as a dirname inside the published netdump.
	// Avoid characters which are not suitable for filenames (across all OSes).
	RequestName string
	// NetTrace : summary of all network operations performed from within the given request.
	NetTrace nettrace.AnyNetTrace
	// PacketCaptures obtained for selected interfaces during the request execution.
	PacketCaptures []nettrace.PacketCapture
}

type fileToDump struct {
	srcPath string
	dstPath string
}

// Files created by EVE or the EVE installer that will be copied into each network dump.
var eveFilesToDump = [...]fileToDump{
	{
		srcPath: "/run/eve-release",
		dstPath: "eve/version.txt",
	},
	{
		srcPath: "/persist/status/uuid",
		dstPath: "eve/device-uuid.txt",
	},
	{
		srcPath: "/config/server",
		dstPath: "eve/controller.txt",
	},
	{
		srcPath: "/run/nim-current-state.dot",
		dstPath: "eve/nim-current-state.dot",
	},
	{
		srcPath: "/run/nim-intended-state.dot",
		dstPath: "eve/nim-intended-state.dot",
	},
	{
		srcPath: "/run/zedrouter-current-state.dot",
		dstPath: "eve/zedrouter-current-state.dot",
	},
	{
		srcPath: "/run/zedrouter-intended-state.dot",
		dstPath: "eve/zedrouter-intended-state.dot",
	},
	{
		srcPath: "/run/nim/DeviceNetworkStatus/global.json",
		dstPath: "eve/dns.json",
	},
	{
		srcPath: "/persist/status/nim/DevicePortConfigList/global.json",
		dstPath: "eve/dpcl.json",
	},
	{
		srcPath: "/run/domainmgr/AssignableAdapters/global.json",
		dstPath: "eve/aa.json",
	},
	{
		srcPath: "/run/wwan/config.json",
		dstPath: "eve/wwan-config.json",
	},
	{
		srcPath: "/run/wwan/status.json",
		dstPath: "eve/wwan-status.json",
	},
	{
		srcPath: "/run/wwan/metrics.json",
		dstPath: "eve/wwan-metrics.json",
	},
}

// Find references to routing tables from "ip rule list".
var rtLookupRE = regexp.MustCompile(` lookup (\d+)`)

// LastPublishAt returns timestamp of the last publication for any of the given topics.
// Returns zero timestamp (and nil error) if nothing has been published yet.
func (dumper *NetDumper) LastPublishAt(topics ...string) (time.Time, error) {
	var lastPub time.Time
	// ReadDir returns files sorted in the ascending order
	// (with our filename layout this means starting with the oldest).
	dirEntries, err := os.ReadDir(netdumpDir)
	if err != nil {
		if os.IsNotExist(err) {
			return lastPub, nil
		}
		return lastPub, fmt.Errorf("netdump: failed to list directory %s: %w",
			netdumpDir, err)
	}
	for _, topic := range topics {
		netdumpPrefix := topic + "-"
		for i := len(dirEntries) - 1; i >= 0; i-- {
			filename := dirEntries[i].Name()
			if !strings.HasSuffix(filename, netdumpExtension) ||
				!strings.HasPrefix(filename, netdumpPrefix) {
				continue
			}
			timeStr := strings.TrimPrefix(filename, netdumpPrefix)
			timeStr = strings.TrimSuffix(timeStr, netdumpExtension)
			timestamp, err := time.ParseInLocation(netdumpTimestampFormat, timeStr, time.UTC)
			if err != nil {
				return time.Time{}, fmt.Errorf("netdump: failed to parse timestamp %s: %w",
					timeStr, err)
			}
			if lastPub.IsZero() || timestamp.After(lastPub) {
				lastPub = timestamp
			}
			break // next topic
		}
	}
	return lastPub, nil
}

// Publish a single netdump archive, containing information such as the current
// DPCL (DevicePortConfigList), DNS (DeviceNetworkStatus), ifconfig output, DHCP
// leases, wwan status and more.
// Additionally, it is possible to attach traces and packet captures recorded
// during an execution of one or more network requests (i.e. requests targeted
// at remote endpoints and carried over the network).
// In order to avoid race conditions between microservices, each microservice
// should use different topic(s) (e.g. topic = microservice name).
// Topic name should not contain characters which are not suitable for filenames
// (across all OSes).
func (dumper *NetDumper) Publish(topic string,
	requests ...TracedNetRequest) (filepath string, err error) {

	// Generate name for the network dump.
	timestamp := time.Now().UTC()
	netdumpPrefix := topic + "-"
	netdumpName := netdumpPrefix + timestamp.Format(netdumpTimestampFormat)
	filepath = path.Join(netdumpDir, netdumpName+netdumpExtension)

	// Create directories inside the archive.
	files := []fileForTar{
		{
			dstPath: netdumpName,
			isDir:   true,
		},
		{
			dstPath: path.Join(netdumpName, "eve"),
			isDir:   true,
		},
		{
			dstPath: path.Join(netdumpName, "linux"),
			isDir:   true,
		},
	}
	if len(requests) > 0 {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "requests"),
			isDir:   true,
		})
	}

	// Include some files written by EVE or EVE installer that contain
	// information useful for network troubleshooting.
	for _, file := range eveFilesToDump {
		fileInfo, err := os.Stat(file.srcPath)
		if err != nil {
			// File is probably missing, skip it.
			continue
		}
		fileHandle, err := os.Open(file.srcPath)
		if err != nil {
			continue
		}
		defer fileHandle.Close()
		files = append(files, fileForTar{
			info:    fileInfo,
			dstPath: path.Join(netdumpName, file.dstPath),
			content: fileHandle,
		})
	}

	// Include Golang version in the netdump.
	if goVer := runtime.Version(); goVer != "" {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "eve/go-version.txt"),
			content: strings.NewReader(goVer),
		})
	}

	// Capture and add into the archive some config/state data from the Linux network stack.
	if output, err := exec.Command("ifconfig").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/ifconfig.txt"),
			content: strings.NewReader(string(output)),
		})
	}
	if output, err := exec.Command("ip", "-s", "link").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/iplink.txt"),
			content: strings.NewReader(string(output)),
		})
	}
	if output, err := exec.Command("arp", "-n").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/arp.txt"),
			content: strings.NewReader(string(output)),
		})
	}
	routingTables := []string{"main"}
	if output, err := exec.Command("ip", "rule", "list").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/iprule.txt"),
			content: strings.NewReader(string(output)),
		})
		for _, rtLookup := range rtLookupRE.FindAllStringSubmatch(string(output), -1) {
			if len(rtLookup) == 2 {
				routingTables = append(routingTables, rtLookup[1])
			}
		}
	}
	for _, rt := range routingTables {
		cmd := exec.Command("ip", "route", "show", "table", rt)
		if output, err := cmd.CombinedOutput(); err == nil {
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("%s/linux/iproute-%s.txt", netdumpName, rt),
				content: strings.NewReader(string(output)),
			})
		}
	}
	if netIfaces, err := net.Interfaces(); err == nil {
		for _, netIface := range netIfaces {
			cmd := exec.Command("dhcpcd", "-U", "-4", netIface.Name)
			output, err := cmd.CombinedOutput()
			if err != nil {
				continue
			}
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("%s/linux/dhcp-lease-%s.txt",
					netdumpName, netIface.Name),
				content: strings.NewReader(string(output)),
			})
		}
	}
	var iptables = []string{"raw", "filter", "mangle", "nat"}
	for _, iptable := range iptables {
		cmd := exec.Command("iptables", "-L", "-v", "-n", "--line-numbers", "-t", iptable)
		if output, err := cmd.CombinedOutput(); err == nil {
			files = append(files, fileForTar{
				dstPath: fmt.Sprintf("%s/linux/iptables-%s.txt", netdumpName, iptable),
				content: strings.NewReader(string(output)),
			})
		}
	}
	if output, err := exec.Command("netstat", "-tuapn").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/netstat.txt"),
			content: strings.NewReader(string(output)),
		})
	}
	// Include listing of processes to check if wpa_supplicant, dhcpcd, etc., are running.
	if output, err := exec.Command("ps", "-e", "-f").CombinedOutput(); err == nil {
		files = append(files, fileForTar{
			dstPath: path.Join(netdumpName, "linux/ps.txt"),
			content: strings.NewReader(string(output)),
		})
	}

	// Attach provided network traces and packet captures.
	for _, req := range requests {
		dirName := path.Join(netdumpName, "requests", req.RequestName)
		files = append(files, fileForTar{
			dstPath: dirName,
			isDir:   true,
		})
		if req.NetTrace != nil {
			traceInJSON, err := json.MarshalIndent(req.NetTrace, "", "  ")
			if err != nil {
				err = fmt.Errorf("netdump: failed to marshal nettrace of the request "+
					"%s: %w", req.RequestName, err)
				return "", err
			}
			files = append(files, fileForTar{
				dstPath: path.Join(dirName, "nettrace.json"),
				content: strings.NewReader(string(traceInJSON)),
			})
		}
		for _, pcap := range req.PacketCaptures {
			pcapName := pcap.InterfaceName
			if pcap.Truncated {
				pcapName += "-truncated"
			}
			if !pcap.WithTCPPayload {
				pcapName += "-nopayload"
			}
			pcapName += ".pcap"
			buf := new(strings.Builder)
			err = pcap.WriteTo(buf)
			if err != nil {
				return "", fmt.Errorf("netdump: failed to write PCAP %s: %w", pcapName, err)
			}
			files = append(files, fileForTar{
				dstPath: path.Join(dirName, pcapName),
				content: strings.NewReader(buf.String()),
			})
		}
	}

	// Remove the oldest network dump if needed to avoid exceeding the count limit.
	if err = os.MkdirAll(netdumpDir, 0755); err != nil {
		return "", fmt.Errorf("netdump: failed to create directory %s: %w",
			netdumpDir, err)
	}
	if dumper.MaxDumpsPerTopic > 0 {
		dirEntries, err := os.ReadDir(netdumpDir)
		if err != nil {
			return "", fmt.Errorf("netdump: failed to list directory %s: %w",
				netdumpDir, err)
		}
		var publishedDumps []string
		for _, dirEntry := range dirEntries {
			filename := dirEntry.Name()
			if strings.HasPrefix(filename, netdumpPrefix) &&
				strings.HasSuffix(filename, netdumpExtension) {
				publishedDumps = append(publishedDumps, filename)
			}
		}
		// publishedDumps are sorted in the ascending order (starting with oldest)
		// by ReadDir. We should keep at most the last dumper.MaxDumpsPerTopic-1 dumps.
		for len(publishedDumps) >= dumper.MaxDumpsPerTopic {
			dumpPath := path.Join(netdumpDir, publishedDumps[0])
			err := os.Remove(dumpPath)
			if err != nil {
				return "", fmt.Errorf("netdump: failed to remove older network dump %s: %w",
					dumpPath, err)
			}
			publishedDumps = publishedDumps[1:]
		}
	}

	// Write network dump into the persist partition.
	err = createTarGz(filepath, files)
	if err != nil {
		// Error is already formatted with "netdump:" prefix by createTarGz.
		return "", err
	}
	return filepath, nil
}
