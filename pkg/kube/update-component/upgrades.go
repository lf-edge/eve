// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

//
// A kubernetes component/app upgrade wrapper.
// 	- guard against incompatible versions
//	- easier parsing of uptime/readiness instead of in bash scripts
//
// Examples:
//  Compare running/expected versions: upgrade-component --component longhorn --versions-file /usr/bin/expected_versions.yaml --compare
//	Upgrade: upgrade-component --component longhorn --versions-file /usr/bin/expected_versions.yaml -upgrade
//

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
	"gopkg.in/yaml.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// All Supported Components
	compNameMultus   = "multus"
	compNameKubevirt = "kubevirt"
	compNameCdi      = "cdi"
	compNameLonghorn = "longhorn"

	expectedUptimePostUpgrade = time.Second * 30
	upgradePollWaitSeconds    = 30
	kubeConfigFile            = "/etc/rancher/k3s/k3s.yaml"

	emptyVersion = "v0.0.0"

	logfileDir    = "/persist/kubelog/"
	logfile       = logfileDir + "upgrade-component.log"
	logMaxSize    = 10  // 10 Mbytes in size
	logMaxBackups = 3   // old log files to retain
	logMaxAge     = 365 // days to retain old log files

	// Keep in sync with kube-init's mgmtproxy.URL and DisableFlag.
	// KubectlApply downloads upgrade YAMLs from HTTPS URLs through pillar's
	// mgmtproxy so the upgrade path honors network.download.max.cost.
	mgmtproxyURL         = "http://127.0.0.1:5443"
	mgmtproxyDisableFlag = "/run/kube/mgmtproxy-disable"
)

var (
	// ForceUpgrade ignores component version constraints and requests upgrade.
	ForceUpgrade = false
	logFile      *lumberjack.Logger
)

// componentsNewVersionsTable is a map of versions the system will upgrade to
var componentNewVersionsTable = map[string]string{
	compNameMultus:   emptyVersion,
	compNameKubevirt: emptyVersion,
	compNameCdi:      emptyVersion,
	compNameLonghorn: emptyVersion,
}

// KubeComponent implements upgrade processing for various kubernetes apps/components
type KubeComponent interface {
	GetVersion() (string, error)

	UpgradeSupported(sourceVer string, destVer string) error

	// Caller should be expecting a time stamp for when the app reached condition ready
	// Error will return (time.Now(), err) so uptimestamp will never stop increasing
	Uptime(version string) (time.Time, error)

	// Ready is a function that returns nil if the component is online
	// Is the specified component online at the requested version?
	Ready(version string) error

	// ComponentUpgradeStart is a function that initiates an upgrade of the component to the specified version
	UpgradeStart(version string) error
}

type commonComponent struct {
	cs *kubernetes.Clientset
}

// isHTTPSURL reports whether path is an https URL. Only https goes through
// mgmtproxy, which is CONNECT-only.
func isHTTPSURL(path string) bool {
	return strings.HasPrefix(path, "https://")
}

// mgmtproxyEnabled mirrors cluster-utils.sh:mgmtproxy_enabled — the operator
// off-switch is the presence of /run/kube/mgmtproxy-disable. Absent file means
// proxy injection is enabled; presence means bypass.
func mgmtproxyEnabled() bool {
	_, err := os.Stat(mgmtproxyDisableFlag)
	return os.IsNotExist(err)
}

// kubectlApplyArgs applies server-side under kube-init's field manager, as
// kube-init installs the components.
func kubectlApplyArgs(src string) []string {
	return []string{"apply", "--server-side", "--force-conflicts",
		"--field-manager=" + fieldManager, "-f", src}
}

// manifestFetchTimeout bounds the download of an upgrade manifest.
const manifestFetchTimeout = 5 * time.Minute

// fetchManifest downloads an http(s) manifest to a temp file, so the
// ownership step and the apply read one copy. The caller removes the file.
func fetchManifest(url string) (string, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	switch {
	case isHTTPSURL(url) && mgmtproxyEnabled():
		proxyURL, err := neturl.Parse(mgmtproxyURL)
		if err != nil {
			return "", err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
		log.Printf("KubectlApply: routing through mgmtproxy (%s): %s", mgmtproxyURL, url)
	case isHTTPSURL(url):
		log.Printf("KubectlApply: mgmtproxy disabled (%s present), fetching direct: %s",
			mgmtproxyDisableFlag, url)
	default:
		log.Printf("KubectlApply: plain-HTTP URL not routed through mgmtproxy, fetching direct: %s", url)
	}
	client := &http.Client{Transport: transport, Timeout: manifestFetchTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	f, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		return "", err
	}
	_, err = io.Copy(f, resp.Body)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func (ctx *commonComponent) KubectlApply(path string) error {
	src := path
	if isHTTPSURL(path) || strings.HasPrefix(path, "http://") {
		file, err := fetchManifest(path)
		if err != nil {
			return fmt.Errorf("fetch %s: %w", path, err)
		}
		defer func() { _ = os.Remove(file) }()
		src = file
	}
	if err := adoptInstalledFields(src); err != nil {
		log.Printf("WARNING: adopt installed fields of %s: %v", path, err)
	}
	cmd := exec.Command("kubectl", kubectlApplyArgs(src)...)
	var outStr strings.Builder
	var errStr strings.Builder
	cmd.Stdout = &outStr
	cmd.Stderr = &errStr
	err := cmd.Run()
	if err != nil {
		rc := cmd.ProcessState.ExitCode()
		return fmt.Errorf("apply %s, rc: %d, stdout: %s, stderr: %s, err: %v", path, rc, outStr.String(), errStr.String(), err)
	}
	log.Printf("apply %s, stdout: %s, stderr: %s\n", path, outStr.String(), errStr.String())
	return nil
}

// GetKubeConfig : Get handle to Kubernetes config
func GetKubeConfig() (*rest.Config, error) {
	// Build the configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeConfigFile)
	if err != nil {
		return nil, err
	}
	// Set a generous default timeout
	// instead of 0 default no timeout
	config.Timeout = time.Second * 60
	return config, nil
}

// GetClientSet : Get handle to kubernetes clientset
func GetClientSet() (*kubernetes.Clientset, error) {

	// Build the configuration from the provided kubeconfig file
	config, err := GetKubeConfig()
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return clientset, nil
}

// Versions is a structure to map the expected upgrade versions
//
//	in a yaml file of the kube service container
type Versions struct {
	Multus   string `yaml:"multus"`
	Kubevirt string `yaml:"kubevirt"`
	Cdi      string `yaml:"cdi"`
	Longhorn string `yaml:"longhorn"`
}

func getComponentHandler(cs *kubernetes.Clientset, comp string) KubeComponent {
	common := commonComponent{cs: cs}
	switch comp {
	case compNameMultus:
		return &multusComponent{common}
	case compNameKubevirt:
		return &kubevirtComponent{common}
	case compNameCdi:
		return &cdiComponent{common}
	case compNameLonghorn:
		return &longhornComponent{common}
	}
	return nil
}

func main() {
	// Actions
	beginUpgradesPtr := flag.Bool("upgrade", false, "Begin upgrades")
	onlyCompareVersionPtr := flag.Bool("compare", false, "Just compare current version, return 0 for matching, 1 for not matching")
	checkCompReadyFlag := flag.Bool("check-comp-ready", false, "Check if component is ready, according to its daemonsets (rc 0 for success)")
	checkAPIReadyFlag := flag.Bool("check-api-ready", false, "Check if api is responding, (rc 0 for success)")
	getCompUptimeFlag := flag.Bool("get-uptime", false, "Print component uptime in seconds")

	// Options
	forcePtr := flag.Bool("f", false, "Force: skip uptime checks and version constraints")
	versionsFilePtr := flag.String("versions-file", "", "Versions file")
	componentPtr := flag.String("component", "", "Component to upgrade")
	flag.Parse()

	ForceUpgrade = *forcePtr

	//
	// Setup Logging
	//
	if _, err := os.Stat(logfileDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logfileDir, 0755); err != nil {
			os.Exit(1)
		}
	}
	logFile = &lumberjack.Logger{
		Filename:   logfile,       // Path to the log file.
		MaxSize:    logMaxSize,    // Maximum size in megabytes before rotation.
		MaxBackups: logMaxBackups, // Maximum number of old log files to retain.
		MaxAge:     logMaxAge,     // Maximum number of days to retain old log files.
		Compress:   true,          // Whether to compress rotated log files.
		LocalTime:  true,          // Use the local time zone for file names.
	}
	log.SetOutput(logFile)
	defer logFile.Close()

	//
	// Get Kubernetes handle
	//
	clientset, err := GetClientSet()
	if err != nil {
		log.Printf("Failed to get clientset %v\n", err)
		os.Exit(1)
	}

	//
	// A basic lightweight call to see if k3s is running
	//
	if *checkAPIReadyFlag {
		nodes, err := clientset.CoreV1().Nodes().List(context.Background(), metav1.ListOptions{})
		if err != nil || (len(nodes.Items) < 1) {
			os.Exit(1)
		}
		os.Exit(0)
	}

	//
	// Read in destination upgrade versions
	//
	if *versionsFilePtr != "" {
		if _, err := os.Stat(*versionsFilePtr); err == nil {
			var versions = Versions{}
			yamlData, err := os.ReadFile(*versionsFilePtr)
			if err != nil {
				log.Print(fmt.Errorf("unable to read in versions file at path:%s err:%v", *versionsFilePtr, err))
				os.Exit(1)
			}
			err = yaml.UnmarshalStrict(yamlData, &versions)
			if err != nil {
				log.Print(err.Error())
				os.Exit(1)
			}
			if versions.Multus != "" {
				componentNewVersionsTable[compNameMultus] = versions.Multus
			}
			if versions.Kubevirt != "" {
				componentNewVersionsTable[compNameKubevirt] = versions.Kubevirt
			}
			if versions.Cdi != "" {
				componentNewVersionsTable[compNameCdi] = versions.Cdi
			}
			if versions.Longhorn != "" {
				componentNewVersionsTable[compNameLonghorn] = versions.Longhorn
			}
		}
	}

	//
	// Read in running (source) versions
	//
	component := *componentPtr
	var componentCurrentVersions = map[string]string{
		compNameMultus:   "",
		compNameKubevirt: "",
		compNameLonghorn: "",
		compNameCdi:      "",
	}
	compHandler := getComponentHandler(clientset, component)
	currentVersion, err := compHandler.GetVersion()
	if err != nil {
		log.Printf("Error retrieving version for component: %s, error: %v\n", component, err)
		os.Exit(1)
	}
	componentCurrentVersions[component] = currentVersion

	ready := false
	var uptimeSeconds float64
	if err := compHandler.Ready(currentVersion); err == nil {
		ready = true
		uptimeStamp, err := compHandler.Uptime(currentVersion)
		if err != nil {
			log.Print("Component: " + component + " uptime err:" + err.Error())
			os.Exit(1)
		} else {
			uptimeSeconds = time.Since(uptimeStamp).Seconds()
		}
	}

	//
	// Determine if upgrade necessary
	//
	if *onlyCompareVersionPtr {
		log.Printf("Component:%s ready:%v running:%s expected_version:%s uptime_seconds:%f",
			component, ready, componentCurrentVersions[component], componentNewVersionsTable[component], uptimeSeconds)
		if componentCurrentVersions[component] == componentNewVersionsTable[component] {
			os.Exit(0)
		}
		os.Exit(1)
	}

	//
	// Is it ready, 1 is bool true but 0 is success unix code
	//
	if *checkCompReadyFlag {
		if !ready {
			os.Exit(1)
		}
		os.Exit(0)
	}

	//
	// Comp Uptime printed
	//
	if *getCompUptimeFlag {
		fmt.Print(uint64(uptimeSeconds))
		os.Exit(0)
	}

	//
	// Begin Update
	//
	if *beginUpgradesPtr {
		//
		// Pre-Upgrade Health Check
		//
		log.Print("Checking component health pre-upgrade")
		currentVersion := componentCurrentVersions[component]
		for {
			if err := compHandler.Ready(currentVersion); err != nil {
				log.Print("Component: " + component + " is not ready at version:" + currentVersion + " err: " + err.Error())
				time.Sleep(upgradePollWaitSeconds * time.Second)
			} else {
				log.Print("Component: " + component + " is ready")
				break
			}
		}

		//
		// Version compatibility check
		//
		newVersion := componentNewVersionsTable[component]
		log.Printf("new-phase:upgrade-start component:%s srcVer:%s dstVer:%s\n", component, currentVersion, newVersion)
		err = compHandler.UpgradeSupported(currentVersion, newVersion)
		if err != nil && !ForceUpgrade {
			log.Printf("Component: %s denied upgrade srcVer:%s dstVer:%s err:%v\n", component, currentVersion, newVersion, err)
		} else {
			err = compHandler.UpgradeStart(newVersion)
			if err != nil {
				log.Printf("Component: %s upgrade init srcVer:%s dstVer:%s error: %v\n", component, currentVersion, newVersion, err)
				os.Exit(1)
			}

			log.Printf("new-phase:post-upgrade ver:%s component:%s\n", newVersion, component)
			var updated = false
			for !updated {
				time.Sleep(upgradePollWaitSeconds * time.Second)
				foundVersion, err := compHandler.GetVersion()
				if err != nil {
					log.Printf("post-upgrade component:%s get version err:%v\n", component, err)
					os.Exit(1)
				}
				log.Printf("post-upgrade component:%s version:%s waiting for version:%s\n", component, foundVersion, newVersion)
				if foundVersion == newVersion {
					updated = true
					componentCurrentVersions[component] = newVersion
				}
			}

			//
			// Wait for new version to reach running/ready
			//
			var acceptableUptime = false
			for !acceptableUptime {
				time.Sleep(upgradePollWaitSeconds * time.Second)
				uptime, err := compHandler.Uptime(newVersion)
				if err != nil {
					log.Printf("post-upgrade uptime get error:%v", err)
					continue
				}
				uptimeDuration := time.Since(uptime)
				if uptimeDuration >= expectedUptimePostUpgrade {
					acceptableUptime = true
				}
				log.Printf("Waiting for steady uptime of component:%s, uptime_seconds:%f", component, uptimeDuration.Seconds())
			}
		}
	}
}
