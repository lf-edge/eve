// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package configitems

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/lf-edge/eve-libs/depgraph"
	"github.com/lf-edge/eve-libs/reconciler"
	log "github.com/sirupsen/logrus"
)

const (
	scepSrvBinary      = "/usr/local/bin/scepserver"
	scepSrvRunDir      = "/run/scepsrv"
	scepSrvDefaultPort = uint16(80)

	scepSrvStartTimeout = 3 * time.Second
	scepSrvStopTimeout  = 5 * time.Second
)

// SCEPServer : Simple Certificate Enrolment Protocol (SCEP) server.
type SCEPServer struct {
	// ServerName : logical name for the SCEP server.
	ServerName string
	// NetNamespace : network namespace where the server should be running.
	NetNamespace string
	// VethName : logical name of the veth pair on which the server operates.
	// (other types of interfaces are currently not supported)
	VethName string
	// TCP port on which the SCEP server listens.
	// If not specified, the default SCEP port (80) is used.
	Port uint16
	// Certificate Authority (CA) certificate in PEM format.
	// Used by the SCEP server to sign issued certificates.
	CACertPEM string
	// Private key of the Certificate Authority in PEM format.
	CAKeyPEM string
	// Optional SCEP challenge password (shared secret).
	// When set, clients must present this password during enrollment.
	ChallengeSecret string
}

// Name of the SCEP server.
func (s SCEPServer) Name() string {
	return s.ServerName
}

// Label assigned to the SCEP server.
func (s SCEPServer) Label() string {
	return s.ServerName + " (SCEP server)"
}

// Type assigned to SCEPServer.
func (s SCEPServer) Type() string {
	return SCEPServerTypename
}

// Equal is a comparison method for two equally-named HttpServer instances.
func (s SCEPServer) Equal(other depgraph.Item) bool {
	s2 := other.(SCEPServer)
	return s.NetNamespace == s2.NetNamespace &&
		s.VethName == s2.VethName &&
		s.Port == s2.Port &&
		s.CACertPEM == s2.CACertPEM &&
		s.CAKeyPEM == s2.CAKeyPEM &&
		s.ChallengeSecret == s2.ChallengeSecret
}

// External returns false.
func (s SCEPServer) External() bool {
	return false
}

// String describes the SCEP server.
func (s SCEPServer) String() string {
	return fmt.Sprintf("SCEP server: %#+v", s)
}

// Dependencies lists the (optional) veth and network namespace as dependencies.
func (s SCEPServer) Dependencies() (deps []depgraph.Dependency) {
	deps = append(deps, depgraph.Dependency{
		RequiredItem: depgraph.ItemRef{
			ItemType: NetNamespaceTypename,
			ItemName: normNetNsName(s.NetNamespace),
		},
		Description: "Network namespace must exist",
	})
	if s.VethName != "" {
		deps = append(deps, depgraph.Dependency{
			RequiredItem: depgraph.ItemRef{
				ItemType: VethTypename,
				ItemName: s.VethName,
			},
			Description: "veth interface must exist",
		})
	}
	return deps
}

// SCEPServerConfigurator implements Configurator interface for SCEPServer.
type SCEPServerConfigurator struct{}

// Create starts SCEP server.
func (c *SCEPServerConfigurator) Create(ctx context.Context, item depgraph.Item) error {
	config := item.(SCEPServer)
	done := reconciler.ContinueInBackground(ctx)
	if err := prepareSCEPCertDir(config); err != nil {
		return err
	}
	go func() {
		err := startSCEPSrv(config)
		done(err)
	}()
	return nil
}

// Modify is not implemented.
func (c *SCEPServerConfigurator) Modify(ctx context.Context,
	oldItem, newItem depgraph.Item) (err error) {
	return errors.New("not implemented")
}

// Delete stops SCEP server.
func (c *SCEPServerConfigurator) Delete(ctx context.Context, item depgraph.Item) error {
	config := item.(SCEPServer)
	done := reconciler.ContinueInBackground(ctx)
	go func() {
		err := stopSCEPSrv(config.ServerName)
		if err == nil {
			// ignore errors from here
			_ = removeSCEPSrvLogFile(config.ServerName)
			_ = removeSCEPSrvPidFile(config.ServerName)
			_ = removeSCEPSrvCertDir(config.ServerName)
		}
		done(err)
	}()
	return nil
}

// NeedsRecreate always returns true - Modify is not implemented.
func (c *SCEPServerConfigurator) NeedsRecreate(
	oldItem, newItem depgraph.Item) (recreate bool) {
	return true
}

func scepSrvPidFile(srvName string) string {
	return filepath.Join(scepSrvRunDir, srvName+".pid")
}

func scepSrvLogFile(srvName string) string {
	return filepath.Join(scepSrvRunDir, srvName+".log")
}

func scepSrvCertDir(srvName string) string {
	return filepath.Join(scepSrvRunDir, srvName+"-certs")
}

func removeSCEPSrvPidFile(srvName string) error {
	pidPath := scepSrvPidFile(srvName)
	if err := os.Remove(pidPath); err != nil {
		err = fmt.Errorf("failed to remove SCEP server PID file %s: %w",
			pidPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeSCEPSrvLogFile(srvName string) error {
	logPath := scepSrvLogFile(srvName)
	if err := os.Remove(logPath); err != nil {
		err = fmt.Errorf("failed to remove SCEP server log file %s: %w",
			logPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func removeSCEPSrvCertDir(srvName string) error {
	dirPath := scepSrvCertDir(srvName)
	if err := os.RemoveAll(dirPath); err != nil {
		err = fmt.Errorf("failed to remove SCEP server certificate directory %s: %w",
			dirPath, err)
		log.Error(err)
		return err
	}
	return nil
}

func prepareSCEPCertDir(config SCEPServer) error {
	if err := ensureDir(scepSrvRunDir); err != nil {
		return err
	}
	certDir := scepSrvCertDir(config.ServerName)
	if err := ensureDir(certDir); err != nil {
		return err
	}

	// Write CA certificate
	caCertPath := filepath.Join(certDir, "ca.pem")
	if err := os.WriteFile(caCertPath, []byte(config.CACertPEM), 0o644); err != nil {
		return fmt.Errorf("failed to write SCEP CA certificate: %w", err)
	}

	// Write CA private key
	caKeyPath := filepath.Join(certDir, "ca.key")
	if err := os.WriteFile(caKeyPath, []byte(config.CAKeyPEM), 0o600); err != nil {
		return fmt.Errorf("failed to write SCEP CA private key: %w", err)
	}
	return nil
}

func startSCEPSrv(config SCEPServer) error {
	cmd := scepSrvBinary
	port := scepSrvDefaultPort
	if config.Port != 0 {
		port = config.Port
	}

	args := []string{
		"-depot", scepSrvCertDir(config.ServerName),
		"-port", strconv.Itoa(int(port)),
		"-allowrenew", "0",
	}

	if config.ChallengeSecret != "" {
		args = append(args, "-challenge", config.ChallengeSecret)
	}

	pidFile := scepSrvPidFile(config.ServerName)
	logFile := scepSrvLogFile(config.ServerName)
	return startProcess(config.NetNamespace, cmd, args, pidFile, logFile,
		scepSrvStartTimeout, true, true)
}

func stopSCEPSrv(srvName string) error {
	pidFile := scepSrvPidFile(srvName)
	return stopProcess(pidFile, scepSrvStopTimeout)
}
