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
	"bytes"
	"context"
	"errors"
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

	// Bounds on the waits of one --upgrade run, so that it always ends
	// and its caller can report a result.
	preUpgradeReadyTimeout = 10 * time.Minute
	upgradeVersionTimeout  = 20 * time.Minute
	upgradeUptimeTimeout   = 5 * time.Minute

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

// finalizer is implemented by components that have a step to run once an
// upgrade to version has fully converged.
type finalizer interface {
	Finalize(version string) error
}

// resumer is implemented by components that can tell whether an earlier,
// interrupted --upgrade already applied version.
type resumer interface {
	Applied(version string) (bool, error)
}

// errNotStarted marks an error from before an upgrade changed anything,
// for a reason that can clear up on its own.
var errNotStarted = errors.New("not started")

// upgradeReady reports whether comp can be upgraded from current to
// target: it is ready at current, or an interrupted run already applied
// target, in which case resume is true and target is applied again.
func upgradeReady(comp KubeComponent, current, target string) (resume bool, err error) {
	err = comp.Ready(current)
	if err == nil {
		return false, nil
	}
	if r, ok := comp.(resumer); ok {
		if applied, aerr := r.Applied(target); aerr == nil && applied {
			return true, nil
		}
	}
	return false, err
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
	return applyManifest(src, path)
}

// applyManifest applies the manifest file src, named name in messages,
// server-side. Its CRDs go first and an error there stops the apply:
// kubectl continues past a rejected object, which would roll out a
// workload on top of a CRD that was not updated.
func applyManifest(src, name string) error {
	if err := adoptInstalledFields(src); err != nil {
		log.Printf("WARNING: adopt installed fields of %s: %v", name, err)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	crds, rest, crdObjs, err := splitManifest(data)
	if err != nil {
		log.Printf("WARNING: split %s: %v; applying it in one step", name, err)
		return kubectlApplyFile(src, name)
	}
	if len(crdObjs) == 0 {
		return kubectlApplyFile(src, name)
	}
	crdFile, err := writeTempManifest(crds)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(crdFile) }()
	if err := applyCRDs(crdFile, crdObjs, name); err != nil {
		return err
	}
	if len(bytes.TrimSpace(rest)) == 0 {
		return nil
	}
	restFile, err := writeTempManifest(rest)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(restFile) }()
	return kubectlApplyFile(restFile, name)
}

func writeTempManifest(data []byte) (string, error) {
	f, err := os.CreateTemp("", "manifest-*.yaml")
	if err != nil {
		return "", err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}

func kubectlApplyFile(file, name string) error {
	cmd := exec.Command("kubectl", kubectlApplyArgs(file)...)
	var outStr strings.Builder
	var errStr strings.Builder
	cmd.Stdout = &outStr
	cmd.Stderr = &errStr
	err := cmd.Run()
	if err != nil {
		rc := cmd.ProcessState.ExitCode()
		return fmt.Errorf("apply %s, rc: %d, stdout: %s, stderr: %s, err: %v", name, rc, outStr.String(), errStr.String(), err)
	}
	log.Printf("apply %s, stdout: %s, stderr: %s\n", name, outStr.String(), errStr.String())
	return nil
}

// KubectlApplyData applies manifest data that was derived from the local
// file at path.
func (ctx *commonComponent) KubectlApplyData(path string, data []byte) error {
	file, err := writeTempManifest(data)
	if err != nil {
		return fmt.Errorf("apply modified %s: %w", path, err)
	}
	defer func() { _ = os.Remove(file) }()
	return applyManifest(file, "modified "+path)
}

// exitNotStarted is the exit code of an --upgrade that stopped before
// changing anything, for a reason that can clear up on its own. The
// caller may run it again later.
const exitNotStarted = 2

// fail records why the run cannot continue, in the log and on stderr for
// the caller, and exits 1.
func fail(format string, args ...interface{}) {
	exitWith(1, format, args...)
}

// notStarted is fail for an --upgrade that has not changed anything yet
// and may succeed if run again later.
func notStarted(format string, args ...interface{}) {
	exitWith(exitNotStarted, format, args...)
}

// report exits with code and tells the caller why on stderr only: it is
// the answer to a probe the caller polls, not an event worth a log line.
func report(code int, format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	if logFile != nil {
		logFile.Close()
	}
	os.Exit(code)
}

func exitWith(code int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	log.Print(msg)
	fmt.Fprintln(os.Stderr, msg)
	if logFile != nil {
		logFile.Close()
	}
	os.Exit(code)
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
	checkCompReadyFlag := flag.Bool("check-comp-ready", false, "Check if component is ready at its expected version (rc 0 for success)")
	checkUpgradeReadyFlag := flag.Bool("check-upgrade-ready", false, "Check if --upgrade would start now (rc 0 yes, 2 no)")
	finalizeFlag := flag.Bool("finalize", false, "Run the component's post-upgrade step, if it has one (rc 0 for success)")
	checkAPIReadyFlag := flag.Bool("check-api-ready", false, "Check if api is responding, (rc 0 for success)")
	getCompUptimeFlag := flag.Bool("get-uptime", false, "Print component uptime in seconds")

	// Options
	forcePtr := flag.Bool("f", false, "Force: ignore component version constraints")
	versionsFilePtr := flag.String("versions-file", "", "Versions file")
	componentPtr := flag.String("component", "", "Component to upgrade")
	flag.Parse()

	ForceUpgrade = *forcePtr

	// A failure to read the cluster before --upgrade changes anything
	// is not the upgrade's: the caller may run it again later.
	startFail := fail
	if *beginUpgradesPtr || *checkUpgradeReadyFlag {
		startFail = notStarted
	}

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
		startFail("Failed to get clientset %v", err)
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
		startFail("Error retrieving version for component: %s, error: %v", component, err)
	}
	componentCurrentVersions[component] = currentVersion

	ready := false
	var uptimeSeconds float64
	if err := compHandler.Ready(currentVersion); err == nil {
		ready = true
		uptimeStamp, err := compHandler.Uptime(currentVersion)
		if err != nil {
			startFail("Component: %s uptime err: %v", component, err)
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
	// Is it ready at the expected version? Checked against the expected
	// version, not the running one, so that it only passes once an upgrade
	// has fully converged.
	//
	if *checkCompReadyFlag {
		expected := componentNewVersionsTable[component]
		if err := compHandler.Ready(expected); err != nil {
			report(1, "Component: %s is not ready at version:%s err: %v", component, expected, err)
		}
		os.Exit(0)
	}

	//
	// Would --upgrade get past its readiness check now? Asks once, waits
	// for nothing.
	//
	if *checkUpgradeReadyFlag {
		target := componentNewVersionsTable[component]
		if _, err := upgradeReady(compHandler, currentVersion, target); err != nil {
			report(exitNotStarted, "Component: %s is not ready at version:%s err: %v",
				component, currentVersion, err)
		}
		os.Exit(0)
	}

	//
	// Post-upgrade step
	//
	if *finalizeFlag {
		if f, ok := compHandler.(finalizer); ok {
			err := f.Finalize(componentNewVersionsTable[component])
			if errors.Is(err, errNotStarted) {
				notStarted("Component: %s finalize: %v", component, err)
			} else if err != nil {
				fail("Component: %s finalize error: %v", component, err)
			}
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
		newVersion := componentNewVersionsTable[component]
		deadline := time.Now().Add(preUpgradeReadyTimeout)
		for {
			resume, err := upgradeReady(compHandler, currentVersion, newVersion)
			if err == nil && resume {
				log.Printf("Component: %s version:%s was already applied by an interrupted run, applying it again",
					component, newVersion)
				break
			}
			if err == nil {
				log.Print("Component: " + component + " is ready")
				break
			}
			log.Print("Component: " + component + " is not ready at version:" + currentVersion + " err: " + err.Error())
			if time.Now().After(deadline) {
				notStarted("Component: %s not ready at version:%s within %s, not upgrading: %v",
					component, currentVersion, preUpgradeReadyTimeout, err)
			}
			time.Sleep(upgradePollWaitSeconds * time.Second)
		}

		//
		// Version compatibility check
		//
		log.Printf("new-phase:upgrade-start component:%s srcVer:%s dstVer:%s\n", component, currentVersion, newVersion)
		err = compHandler.UpgradeSupported(currentVersion, newVersion)
		if err != nil && !ForceUpgrade {
			fail("Component: %s denied upgrade srcVer:%s dstVer:%s err:%v", component, currentVersion, newVersion, err)
		}
		err = compHandler.UpgradeStart(newVersion)
		if errors.Is(err, errNotStarted) {
			notStarted("Component: %s upgrade not started srcVer:%s dstVer:%s: %v", component, currentVersion, newVersion, err)
		} else if err != nil {
			fail("Component: %s upgrade init srcVer:%s dstVer:%s error: %v", component, currentVersion, newVersion, err)
		}

		// The version can take long to move, images are pulled now. Not
		// fatal: the caller's ready check owns the time budget.
		log.Printf("new-phase:post-upgrade ver:%s component:%s\n", newVersion, component)
		deadline = time.Now().Add(upgradeVersionTimeout)
		for {
			time.Sleep(upgradePollWaitSeconds * time.Second)
			foundVersion, err := compHandler.GetVersion()
			if err != nil {
				log.Printf("post-upgrade component:%s get version err:%v", component, err)
			} else {
				log.Printf("post-upgrade component:%s version:%s waiting for version:%s\n", component, foundVersion, newVersion)
				if foundVersion == newVersion {
					break
				}
			}
			if time.Now().After(deadline) {
				log.Printf("Component: %s not at version:%s %s after applying it, leaving it to the ready check",
					component, newVersion, upgradeVersionTimeout)
				os.Exit(0)
			}
		}

		//
		// Wait for new version to reach running/ready. Not fatal: the
		// caller polls --check-comp-ready next.
		//
		deadline = time.Now().Add(upgradeUptimeTimeout)
		for time.Now().Before(deadline) {
			time.Sleep(upgradePollWaitSeconds * time.Second)
			uptime, err := compHandler.Uptime(newVersion)
			if err != nil {
				log.Printf("post-upgrade uptime get error:%v", err)
				continue
			}
			uptimeDuration := time.Since(uptime)
			log.Printf("Waiting for steady uptime of component:%s, uptime_seconds:%f", component, uptimeDuration.Seconds())
			if uptimeDuration >= expectedUptimePostUpgrade {
				break
			}
		}
	}
}
