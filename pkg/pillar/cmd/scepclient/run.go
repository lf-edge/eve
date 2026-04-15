// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package scepclient

import (
	"crypto"
	"log"
	"os"
	"strings"
	"time"

	eveconfig "github.com/lf-edge/eve-api/go/config"
	"github.com/lf-edge/eve-libs/nettrace"
	"github.com/lf-edge/eve/pkg/pillar/agentbase"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/cipher"
	"github.com/lf-edge/eve/pkg/pillar/controllerconn"
	"github.com/lf-edge/eve/pkg/pillar/hardware"
	"github.com/lf-edge/eve/pkg/pillar/netdump"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/utils/wait"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
)

const (
	agentName = "scepclient"
	// Time limits for event loop handlers
	errorTime   = 3 * time.Minute
	warningTime = 40 * time.Second

	// By default, EVE starts renewal attempts after 50% of the certificate’s
	// validity period has elapsed.
	defaultRenewPeriod = uint8(50)

	// Directory inside which enrolled certificates are persistently stored.
	certDir = "/persist/pnac"

	// Even if a TPM is available, the private key used for 802.1X authentication
	// is not stored or sealed in the TPM.
	//
	// The reason is that the key must be accessible to wpa_supplicant, which does
	// not natively support TPM-backed keys. While wpa_supplicant can use private
	// keys via PKCS#11, enabling this would require introducing additional
	// dependencies into EVE (e.g., a PKCS#11 OpenSSL engine and a PKCS#11 module).
	//
	// The only widely used PKCS#11 module known to work reliably with
	// wpa_supplicant is libtpm2-pkcs11, which itself depends on a SQLite database
	// to map PKCS#11 objects to TPM handles. Provisioning this setup typically
	// requires the Python-based tpm2_ptool utility, which would need to be
	// reimplemented in Go since EVE does not ship with a Python interpreter.
	//
	// Given the significant implementation and maintenance overhead, we instead
	// persist the 802.1X private key inside the encrypted vault.
	//
	// From a security perspective, this is acceptable because:
	//   - Management ports can reach the controller even without 802.1X.
	//   - 802.1X is primarily used to enable application connectivity to
	//     authenticated networks.
	//   - If the vault cannot be unlocked (e.g., due to device tampering),
	//     applications cannot start, and 802.1X authentication is unnecessary.
	//   - If the vault is unlocked and the system is compromised at runtime,
	//     an attacker could already use the device as a gateway, meaning
	//     802.1X network access would effectively be compromised regardless.
	//
	// Therefore, storing the key in the encrypted vault provides a reasonable
	// security trade-off without the complexity of TPM-backed PKCS#11 integration.
	privateKeyDir = "/persist/vault/pnac"

	defaultKeyType       = eveconfig.KeyType_KEY_TYPE_RSA_2048
	defaultHashAlgorithm = eveconfig.HashAlgorithm_HASH_ALGORITHM_SHA256

	// Topic for SCEPClient netdumps of successful cert enrollments/renewals.
	netDumpConfigOKTopic = agentName + "-ok"
	// Topic for SCEPClient netdumps of failed cert enrollments/renewals.
	netDumpConfigFailTopic = agentName + "-fail"
)

// SCEPClient is a microservice responsible for enrolling and renewing
// certificates based on SCEPProfile configuration.
//
// For each configured SCEPProfile, it attempts to enroll a single certificate.
// Upon successful enrollment:
//   - The certificate is persisted to a file.
//   - The corresponding private key is securely stored in the vault.
//   - The runtime status is published via EnrolledCertStatus.
//
// The service continuously monitors the certificate’s validity period.
// When the renewal window is reached, it begins attempting renewal and
// continues retrying until the certificate is successfully renewed.
type SCEPClient struct {
	agentbase.AgentBase
	ps     *pubsub.PubSub
	logger *logrus.Logger
	log    *base.LogObject

	httpClient    *controllerconn.Client
	agentMetrics  *controllerconn.AgentMetrics
	cipherMetrics *cipher.AgentMetrics

	subGlobalConfig        pubsub.Subscription
	subDeviceNetworkStatus pubsub.Subscription
	subCachedResolvedIPs   pubsub.Subscription
	subOnboardStatus       pubsub.Subscription
	subControllerCert      pubsub.Subscription
	subEdgeNodeCert        pubsub.Subscription
	subSCEPProfile         pubsub.Subscription
	pubEnrolledCertStatus  pubsub.Publication

	devUUID          uuid.UUID
	globalConfig     *types.ConfigItemValueMap
	devNetworkStatus *types.DeviceNetworkStatus

	iteration          int
	controllerHostname string
	netDumper          *netdump.NetDumper // nil if netdump is disabled

	retryTicker   *time.Ticker
	retryInterval uint32 // in seconds

	sendTimeout uint32 // in seconds
	dialTimeout uint32 // in seconds
}

// SignerAndDecrypter represents a cryptographic key that can both
// sign data and decrypt data. This is used for private keys that
// need to participate in SCEP enrollment (CSR signing) and decrypt
// PKCS#7 certificate envelopes.
type SignerAndDecrypter interface {
	crypto.Signer
	crypto.Decrypter
}

// Run starts the scepclient microservice.
func Run(ps *pubsub.PubSub, loggerArg *logrus.Logger, logArg *base.LogObject,
	arguments []string, baseDir string) int {

	scepClient := &SCEPClient{
		ps:               ps,
		logger:           loggerArg,
		log:              logArg,
		devNetworkStatus: &types.DeviceNetworkStatus{},
		globalConfig:     types.DefaultConfigItemValueMap(),
		agentMetrics:     controllerconn.NewAgentMetrics(),
		cipherMetrics:    cipher.NewAgentMetrics(agentName),
	}
	agentbase.Init(scepClient, loggerArg, logArg, agentName,
		agentbase.WithPidFile(),
		agentbase.WithBaseDir(baseDir),
		agentbase.WithArguments(arguments))

	// Run a periodic timer so we always update StillRunning
	stillRunning := time.NewTicker(25 * time.Second)
	ps.StillRunning(agentName, warningTime, errorTime)

	// Wait until the server file containing the controller hostname is available.
	var err error
	var content []byte
	for len(content) == 0 {
		content, err = os.ReadFile(types.ServerFileName)
		if err != nil {
			scepClient.log.Warnf(
				"Controller endpoint file %q not available yet: %v; retrying",
				types.ServerFileName, err,
			)
		} else if len(content) == 0 {
			scepClient.log.Warnf(
				"Controller endpoint file %q is empty; waiting for valid content",
				types.ServerFileName,
			)
		}
		time.Sleep(10 * time.Second)
		ps.StillRunning(agentName, warningTime, errorTime)
	}

	scepClient.controllerHostname = strings.TrimSpace(string(content))
	scepClient.pubEnrolledCertStatus, err = ps.NewPublication(pubsub.PublicationOptions{
		AgentName:  agentName,
		TopicType:  types.EnrolledCertificateStatus{},
		Persistent: true,
	})

	subGlobalConfig, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.ConfigItemValueMap{},
		Persistent:    false,
		CreateHandler: scepClient.handleGlobalConfigCreate,
		ModifyHandler: scepClient.handleGlobalConfigModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subGlobalConfig = subGlobalConfig
	subGlobalConfig.Activate()

	// Receive the global configuration properties before we start the real work.
	for scepClient.globalConfig == nil {
		scepClient.log.Functionf("Waiting for global config")
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	scepClient.log.Functionf("Received global config")

	subOnboardStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedclient",
		MyAgentName:   agentName,
		TopicImpl:     types.OnboardingStatus{},
		Persistent:    true,
		CreateHandler: scepClient.handleOnboardStatusCreate,
		ModifyHandler: scepClient.handleOnboardStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subOnboardStatus = subOnboardStatus
	subOnboardStatus.Activate()

	// Wait for device to onboard.
	for scepClient.devUUID == uuid.Nil {
		scepClient.log.Functionf("Waiting for device to onboard")
		select {
		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)
		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
	scepClient.log.Functionf("Received device UUID")

	// Wait until the vault is ready. The vault is used by the SCEP client
	// to securely store client private keys.
	err = wait.WaitForVault(ps, scepClient.log, agentName, warningTime, errorTime)
	if err != nil {
		log.Fatal(err)
	}
	scepClient.log.Functionf("Vault is ready")

	// Initialize the HTTP client used for communicating with the SCEP server,
	// either directly or via the controller SCEP proxy.
	scepClient.initHTTPClient()
	err = scepClient.httpClient.UpdateTLSConfig(nil)
	if err != nil {
		log.Fatal(err)
	}

	// All dependencies are ready. Initialize remaining subscriptions and start
	// the main event loop.
	subDeviceNetworkStatus, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "nim",
		MyAgentName:   agentName,
		TopicImpl:     types.DeviceNetworkStatus{},
		CreateHandler: scepClient.handleDevNetStatusCreate,
		ModifyHandler: scepClient.handleDevNetStatusModify,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subDeviceNetworkStatus = subDeviceNetworkStatus
	subDeviceNetworkStatus.Activate()

	subCachedResolvedIPs, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "nim",
		MyAgentName: agentName,
		TopicImpl:   types.CachedResolvedIPs{},
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subCachedResolvedIPs = subCachedResolvedIPs
	subCachedResolvedIPs.Activate()

	// Look for controller certs which will be used for decryption.
	subControllerCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "zedagent",
		MyAgentName: agentName,
		TopicImpl:   types.ControllerCert{},
		Persistent:  true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subControllerCert = subControllerCert
	subControllerCert.Activate()

	// Look for edge node certs which will be used for decryption
	subEdgeNodeCert, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:   "tpmmgr",
		MyAgentName: agentName,
		TopicImpl:   types.EdgeNodeCert{},
		Persistent:  true,
		WarningTime: warningTime,
		ErrorTime:   errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subEdgeNodeCert = subEdgeNodeCert
	subEdgeNodeCert.Activate()

	subSCEPProfile, err := ps.NewSubscription(pubsub.SubscriptionOptions{
		AgentName:     "zedagent",
		MyAgentName:   agentName,
		TopicImpl:     types.SCEPProfile{},
		CreateHandler: scepClient.handleSCEPProfileCreate,
		ModifyHandler: scepClient.handleSCEPProfileModify,
		DeleteHandler: scepClient.handleSCEPProfileDelete,
		WarningTime:   warningTime,
		ErrorTime:     errorTime,
	})
	if err != nil {
		log.Fatal(err)
	}
	scepClient.subSCEPProfile = subSCEPProfile
	subSCEPProfile.Activate()

	// Ticker used to periodically:
	//   - Detect enrolled certificates or private keys that have been lost
	//     (e.g. due to a disk error or vault re-creation) and trigger re-enrollment.
	//   - Retry certificates that previously failed to enroll or renew.
	//   - Re-run enrollment/renewal for certificates for which the SCEP server
	//     returned PENDING (e.g. awaiting administrative approval).
	//   - Check all enrolled certificates and initiate renewal attempts
	//     for those that have entered their renewal window.
	scepClient.retryInterval = scepClient.globalConfig.GlobalValueInt(types.SCEPRetryInterval)
	scepClient.retryTicker = time.NewTicker(
		time.Duration(scepClient.retryInterval) * time.Second)

	// Main event loop.
	for {
		select {
		case change := <-subGlobalConfig.MsgChan():
			subGlobalConfig.ProcessChange(change)

		case change := <-subDeviceNetworkStatus.MsgChan():
			subDeviceNetworkStatus.ProcessChange(change)

		case change := <-subCachedResolvedIPs.MsgChan():
			subCachedResolvedIPs.ProcessChange(change)

		case change := <-subOnboardStatus.MsgChan():
			subOnboardStatus.ProcessChange(change)

		case change := <-subControllerCert.MsgChan():
			subControllerCert.ProcessChange(change)

		case change := <-subEdgeNodeCert.MsgChan():
			subEdgeNodeCert.ProcessChange(change)

		case change := <-subSCEPProfile.MsgChan():
			subSCEPProfile.ProcessChange(change)

		case <-scepClient.retryTicker.C:
			scepClient.retryAndStartRenew()

		case <-stillRunning.C:
		}
		ps.StillRunning(agentName, warningTime, errorTime)
	}
}

func (c *SCEPClient) handleGlobalConfigCreate(_ interface{}, key string, _ interface{}) {
	c.handleGlobalConfig(key)
}

func (c *SCEPClient) handleGlobalConfigModify(_ interface{}, key string, _, _ interface{}) {
	c.handleGlobalConfig(key)
}

func (c *SCEPClient) initHTTPClient() {
	c.sendTimeout = c.globalConfig.GlobalValueInt(types.NetworkSendTimeout)
	c.dialTimeout = c.globalConfig.GlobalValueInt(types.NetworkDialTimeout)
	c.httpClient = controllerconn.NewClient(c.log,
		controllerconn.ClientOptions{
			AgentName:           agentName,
			DeviceNetworkStatus: c.devNetworkStatus,
			NetworkSendTimeout:  time.Duration(c.sendTimeout) * time.Second,
			NetworkDialTimeout:  time.Duration(c.dialTimeout) * time.Second,
			ResolverCacheFunc:   c.getCachedResolvedIPs,
			AgentMetrics:        c.agentMetrics,
			DevSerial:           hardware.GetProductSerial(c.log),
			DevSoftSerial:       hardware.GetSoftSerial(c.log),
			DevUUID:             c.devUUID,
			NoLedManager:        true,
			NetTraceOpts: []nettrace.TraceOpt{
				&nettrace.WithLogging{
					CustomLogger: &base.LogrusWrapper{Log: c.log},
				},
				&nettrace.WithConntrack{},
				&nettrace.WithSockTrace{},
				&nettrace.WithDNSQueryTrace{},
				&nettrace.WithHTTPReqTrace{
					HeaderFields: nettrace.HdrFieldsOptWithValues,
				},
			},
		})
}

func (c *SCEPClient) handleGlobalConfig(key string) {
	if key != "global" {
		c.log.Functionf("handleGlobalConfig: ignoring %s\n", key)
		return
	}
	c.log.Functionf("handleGlobalConfig for %s\n", key)
	gcp := agentlog.HandleGlobalConfig(c.log, c.subGlobalConfig, agentName,
		c.CLIParams().DebugOverride, c.logger)
	if gcp != nil {
		c.globalConfig = gcp
		retryInterval := gcp.GlobalValueInt(types.SCEPRetryInterval)
		if retryInterval != 0 && retryInterval != c.retryInterval {
			c.retryInterval = retryInterval
			if c.retryTicker != nil {
				c.retryTicker.Reset(time.Duration(retryInterval) * time.Second)
			}
			c.log.Noticef("Updated SCEP retry interval to %d seconds", retryInterval)
		}
		sendTimeout := gcp.GlobalValueInt(types.NetworkSendTimeout)
		dialTimeout := gcp.GlobalValueInt(types.NetworkDialTimeout)
		if c.httpClient != nil &&
			(sendTimeout != c.sendTimeout || dialTimeout != c.dialTimeout) {
			c.log.Noticef("Network timeout changed (send: %d->%d, dial: %d->%d), "+
				"recreating HTTP client", c.sendTimeout, sendTimeout,
				c.dialTimeout, dialTimeout)
			prevTLSConfig := c.httpClient.TLSConfig
			c.initHTTPClient()
			c.httpClient.TLSConfig = prevTLSConfig
		}
		netdumpEnabled := gcp.GlobalValueBool(types.NetDumpEnable)
		if netdumpEnabled {
			if c.netDumper == nil {
				c.netDumper = &netdump.NetDumper{}
			}
			maxCount := gcp.GlobalValueInt(types.NetDumpTopicMaxCount)
			c.netDumper.MaxDumpsPerTopic = int(maxCount)
		} else {
			c.netDumper = nil
		}
	}
	c.log.Functionf("handleGlobalConfig done for %s\n", key)
}

func (c *SCEPClient) handleDevNetStatusCreate(
	_ interface{}, key string, status interface{}) {
	c.handleDevNetStatus(key, status)
}

func (c *SCEPClient) handleDevNetStatusModify(
	_ interface{}, key string, status interface{}, _ interface{}) {
	c.handleDevNetStatus(key, status)
}

func (c *SCEPClient) handleDevNetStatus(key string, status interface{}) {
	devNetStatus := status.(types.DeviceNetworkStatus)
	if key != "global" {
		c.log.Functionf("handleDevNetStatus: ignoring %s", key)
		return
	}
	c.log.Functionf("handleDevNetStatus for %s", key)
	wasTesting := c.devNetworkStatus.Testing
	*c.devNetworkStatus = devNetStatus
	c.httpClient.UpdateTLSProxyCerts()
	if wasTesting && !c.devNetworkStatus.Testing {
		// Network testing has just completed (either a new configuration
		// was applied or a fallback was selected). Retry certificate
		// enrollment/renewal after the network state change.
		c.log.Noticef("Network testing completed, " +
			"retrying previously failed enrollments/renewals")
		c.retryAndStartRenew()
	}
	c.log.Functionf("handleDevNetStatus done for %s", key)
}

func (c *SCEPClient) handleOnboardStatusCreate(
	_ interface{}, key string, status interface{}) {
	c.handleOnboardStatus(key, status)
}

func (c *SCEPClient) handleOnboardStatusModify(
	_ interface{}, key string, status interface{}, _ interface{}) {
	c.handleOnboardStatus(key, status)
}

func (c *SCEPClient) handleOnboardStatus(key string, status interface{}) {
	onboardingStatus := status.(types.OnboardingStatus)
	c.devUUID = onboardingStatus.DeviceUUID
}

func (c *SCEPClient) handleSCEPProfileCreate(
	_ interface{}, key string, profile interface{}) {
	scepProfile := profile.(types.SCEPProfile)
	c.handleSCEPProfile(scepProfile, false)
}

func (c *SCEPClient) handleSCEPProfileModify(
	_ interface{}, _ string, newProfile interface{}, oldProfile interface{}) {
	scepProfile := newProfile.(types.SCEPProfile)
	c.handleSCEPProfile(scepProfile, false)
}

func (c *SCEPClient) handleSCEPProfileDelete(
	_ interface{}, _ string, profile interface{}) {
	scepProfile := profile.(types.SCEPProfile)
	c.handleSCEPProfile(scepProfile, true)
}

func (c *SCEPClient) getCachedResolvedIPs(hostname string) []types.CachedIP {
	if c.subCachedResolvedIPs == nil {
		return nil
	}
	if item, err := c.subCachedResolvedIPs.Get(hostname); err == nil {
		return item.(types.CachedResolvedIPs).CachedIPs
	}
	return nil
}
