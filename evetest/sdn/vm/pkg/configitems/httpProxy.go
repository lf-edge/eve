// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	api "github.com/lf-edge/eve/evetest/grpcapi/go"
	goproxycfg "github.com/lf-edge/eve/evetest/sdn/vm/cmd/goproxy/config"
	"github.com/lf-edge/eve/pkg/pillar/utils/generics"
	"github.com/lf-edge/eve/pkg/pillar/utils/netutils"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

const (
	goproxyBinary  = "/usr/local/bin/goproxy"
	goproxyConfDir = "/etc/goproxy"
	goproxyRunDir  = "/run/goproxy"

	goproxyStartTimeout = 3 * time.Second
	goproxyStopTimeout  = 10 * time.Second
)

// HTTPProxy : HTTP(S) proxy
type HTTPProxy struct {
	*api.Proxy
	// ProxyName : logical name for the HTTP proxy.
	ProxyName string
	// NetNamespace : network namespace where the server should be running.
	NetNamespace string
	// VethName : logical name of the veth pair on which the proxy operates.
	// (other types of interfaces are currently not supported)
	// Can be empty (if the proxy is not associated with any particular interface).
	VethName string
	// ListenIPs : IP addresses on which the proxy should listen.
	// Can be empty to listen on all available interfaces instead of just
	// the interfaces with the given host addresses.
	ListenIPs []net.IP
	// Hostname : domain name of the proxy.
	Hostname string
	// HTTPPort : specify on which port+protocol to listen for requests
	// to proxy HTTP traffic.
	// Nil value can be used to disable HTTP proxying.
	HTTPPort *api.ProxyPort
	// HTTPSPorts : specify on which port(s)+protocol(s) to listen
	// for requests to proxy HTTPS traffic.
	// Empty list can be used to disable HTTPS proxying.
	HTTPSPorts []*api.ProxyPort
	// Transparent : enable for transparent proxy (not known to the client).
	Transparent bool
	// Users : define for username/password authentication, leave empty otherwise.
	Users []*api.UserCredentials
}

// Name returns the name of the HTTP proxy item.
func (p HTTPProxy) Name() string {
	return p.ProxyName
}

// Label returns the label of the HTTP proxy item.
func (p HTTPProxy) Label() string {
	return p.ProxyName + " (HTTP proxy)"
}

// Type returns the typename of the HTTP proxy item.
func (p HTTPProxy) Type() string {
	return HTTPProxyTypename
}

// Equal is a comparison method for two equally-named HTTPProxy instances.
func (p HTTPProxy) Equal(other depgraph.Item) bool {
	p2 := other.(HTTPProxy)
	if len(p.Users) != len(p2.Users) {
		return false
	}
	for i := range p.Users {
		if !proto.Equal(p.Users[i], p2.Users[i]) {
			return false
		}
	}
	if len(p.HTTPSPorts) != len(p2.HTTPSPorts) {
		return false
	}
	for i := range p.HTTPSPorts {
		if !proto.Equal(p.HTTPSPorts[i], p2.HTTPSPorts[i]) {
			return false
		}
	}
	return proto.Equal(p.Proxy, p2.Proxy) &&
		p.NetNamespace == p2.NetNamespace &&
		p.VethName == p2.VethName &&
		generics.EqualSetsFn(p.ListenIPs, p2.ListenIPs, netutils.EqualIPs) &&
		p.Hostname == p2.Hostname &&
		proto.Equal(p.HTTPPort, p2.HTTPPort) &&
		p.Transparent == p2.Transparent
}

// External returns false.
func (p HTTPProxy) External() bool {
	return false
}

// String describes the HTTP proxy.
func (p HTTPProxy) String() string {
	return fmt.Sprintf("HTTP proxy: %#+v", p)
}

// Dependencies lists the (optional) veth and network namespace as dependencies.
func (p HTTPProxy) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: NetNamespaceTypename,
			ItemName: normNetNsName(p.NetNamespace),
		},
		Description: "Network namespace must exist",
	})
	if p.VethName != "" {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: p.VethName,
			},
			Description: "veth interface must exist",
		})
	}
	return deps
}

// HTTPProxyConfigurator implements Configurator interface for HTTPProxy.
type HTTPProxyConfigurator struct{}

// Create starts goproxy (see sdn/cmd/goproxy).
func (c *HTTPProxyConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(HTTPProxy)
	if err := c.createGoproxyConfFile(config); err != nil {
		return err
	}
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := startGoproxy(config.ProxyName, config.NetNamespace)
		done(err)
	}()
	return nil
}

func (c *HTTPProxyConfigurator) createGoproxyConfFile(proxy HTTPProxy) error {
	if err := ensureDir(goproxyConfDir); err != nil {
		return err
	}
	proxyName := proxy.ProxyName
	// Prepare configuration.
	listenIPs := make([]string, 0, len(proxy.ListenIPs))
	for _, ip := range proxy.ListenIPs {
		listenIPs = append(listenIPs, ip.String())
	}
	config := goproxycfg.ProxyConfig{
		ListenIPs:   listenIPs,
		Hostname:    proxy.Hostname,
		HTTPPort:    proxy.HTTPPort,
		HTTPSPorts:  proxy.HTTPSPorts,
		Transparent: proxy.Transparent,
		LogFile:     goproxyLogFile(proxyName),
		PidFile:     goproxyPidFile(proxyName),
		Verbose:     true,
		CACertPEM:   proxy.GetCaCertPem(),
		CAKeyPEM:    proxy.GetCaKeyPem(),
		ProxyRules:  proxy.GetProxyRules(),
		Users:       proxy.Users,
	}
	configBytes, err := json.MarshalIndent(config, "", " ")
	if err != nil {
		err = fmt.Errorf("failed to marshal config to JSON: %w", err)
		log.Error(err)
		return err
	}
	// Write configuration to file.
	cfgPath := goproxyConfigPath(proxyName)
	err = os.WriteFile(cfgPath, configBytes, 0644)
	if err != nil {
		err = fmt.Errorf("failed to create config file %s: %w", cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

// Modify is not implemented.
func (c *HTTPProxyConfigurator) Modify(ctx context.Context, oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops goproxy.
func (c *HTTPProxyConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(HTTPProxy)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := stopGoproxy(config.ProxyName)
		if err == nil {
			// ignore errors from here
			_ = removeGoproxyConfFile(config.ProxyName)
			_ = removeGoproxyLogFile(config.ProxyName)
			_ = removeGoproxyPidFile(config.ProxyName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *HTTPProxyConfigurator) NeedsRecreate(oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

func goproxyConfigPath(proxyName string) string {
	return filepath.Join(goproxyConfDir, proxyName+".conf")
}

func goproxyPidFile(proxyName string) string {
	return filepath.Join(goproxyRunDir, proxyName+".pid")
}

func goproxyLogFile(proxyName string) string {
	return filepath.Join(goproxyRunDir, proxyName+".log")
}

func removeGoproxyConfFile(proxyName string) error {
	cfgPath := goproxyConfigPath(proxyName)
	if err := os.Remove(cfgPath); err != nil {
		err = fmt.Errorf("failed to remove goproxy config %s: %w",
			cfgPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeGoproxyPidFile(proxyName string) error {
	pidPath := goproxyPidFile(proxyName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove goproxy PID file %s: %w",
			pidPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeGoproxyLogFile(proxyName string) error {
	logPath := goproxyLogFile(proxyName)
	if err := os.Remove(logPath); err != nil {
		err = fmt.Errorf("failed to remove proxy log file %s: %w",
			logPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func startGoproxy(proxyName, netNamespace string) error {
	if err := ensureDir(goproxyRunDir); err != nil {
		return err
	}
	cfgPath := goproxyConfigPath(proxyName)
	cmd := goproxyBinary
	args := []string{
		"-c",
		cfgPath,
	}
	pidFile := goproxyPidFile(proxyName)
	return startProcess(netNamespace, cmd, args, pidFile, "", goproxyStartTimeout,
		false, true)
}

func stopGoproxy(proxyName string) error {
	pidFile := goproxyPidFile(proxyName)
	return stopProcess(pidFile, goproxyStopTimeout)
}
