// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package portscan scans EVE devices from the network side with nmap and
// checks that whatever they expose is HTTPS-only and refuses anonymous
// access. Its tests cover a standalone device; tests/cluster reuses it for a
// three-node EVE-k cluster.
package portscan

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/lf-edge/eve/evetest"
)

// SSHPort is open only because the harness configures an SSH authorized key
// on every device, which EVE's firewall turns into an ACCEPT rule.
const SSHPort = 22

// OpenPort is one port nmap reported as open on a scanned address.
type OpenPort struct {
	Addr     string
	Protocol string // "tcp" or "udp"
	Port     uint16
	Service  string // nmap's guess from its port table, not a probe result
}

func (p OpenPort) String() string {
	return fmt.Sprintf("%s %d/%s (%s)", p.Addr, p.Port, p.Protocol, p.Service)
}

// The subset of nmap's XML output (-oX) that the helpers below read.
type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     []nmapPort    `xml:"ports>port"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   uint16 `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name string `xml:"name,attr"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapTable struct {
	Key   string     `xml:"key,attr"`
	Elems []nmapElem `xml:"elem"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// runNmap runs nmap from the evetest container, whose default route leads
// through the SDN tunnel to the EVE devices, and parses its XML report.
func runNmap(timeout time.Duration, args ...string) (*nmapRun, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "nmap", append(args, "-oX", "-")...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nmap %s: %w (stderr: %s)",
			strings.Join(args, " "), err, stderr.String())
	}
	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML output: %w", err)
	}
	return &run, nil
}

// ScanOpenPorts SYN-scans every TCP port and UDP-scans every UDP port of
// addrs, returning the ports nmap classifies as "open".
//
// EVE drops unsolicited input on its uplinks, so a UDP port with no listener
// and a filtered one look alike ("open|filtered"). A UDP port is reported open
// only when something answered nmap's probe, which is the externally
// observable exposure this test is after.
func ScanOpenPorts(addrs []string, timeout time.Duration) ([]OpenPort, error) {
	args := []string{"-Pn", "-n", "-sS", "-sU", "-p-", "-T4",
		"--min-rate", "2000", "--max-retries", "1"}
	run, err := runNmap(timeout, append(args, addrs...)...)
	if err != nil {
		return nil, err
	}
	var ports []OpenPort
	for _, host := range run.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		for _, p := range host.Ports {
			if p.State.State != "open" {
				continue
			}
			ports = append(ports, OpenPort{
				Addr:     host.Addresses[0].Addr,
				Protocol: p.Protocol,
				Port:     p.PortID,
				Service:  p.Service.Name,
			})
		}
	}
	return ports, nil
}

// TLSAssessment records how a TCP service holds up against the requirement
// that everything EVE exposes is HTTPS-only and refuses anonymous access.
type TLSAssessment struct {
	// TLS/SSL protocol versions the service accepts, per ssl-enum-ciphers.
	Protocols []string
	// Weakest cipher grade ssl-enum-ciphers assigned (A best, F worst).
	LeastStrength string
	// The TLS session failed after the server asked for a client certificate
	// and got none, i.e. the service admits only mutually authenticated peers.
	ClientCertRequired bool
	// HTTP status of an HTTPS GET carrying no credentials, per path in
	// unauthProbePaths that got an HTTP answer.
	UnauthStatus map[string]int
	// HTTP status of a plaintext GET /; 0 if the service did not answer
	// with HTTP.
	PlaintextStatus int
	// Every way the service falls short; empty means it is locked down.
	Problems []string
}

func (a TLSAssessment) String() string {
	return fmt.Sprintf("protocols=%v leastStrength=%q clientCertRequired=%t "+
		"unauthStatus=%v plaintextStatus=%d problems=%q",
		a.Protocols, a.LeastStrength, a.ClientCertRequired,
		a.UnauthStatus, a.PlaintextStatus, a.Problems)
}

// probeAppUUID names no application; zedkube must refuse an unauthenticated
// request for it before looking it up.
const probeAppUUID = "00000000-0000-0000-0000-000000000000"

// unauthProbePaths are requested without credentials. "/" alone is not
// enough: a service with nothing at the root answers 404 whether or not it
// requires authentication, as the kubelet does, while it answers 401 for
// /pods. The last three are zedkube's cluster-status and App-Tracker
// endpoints on 12346.
var unauthProbePaths = []string{"/", "/pods", "/status",
	"/app/" + probeAppUUID, "/cluster-app/" + probeAppUUID}

// AssessTLSService checks that the TCP service at addr:port speaks only TLS
// 1.2 or newer with strong ciphers, never answers plaintext HTTP, and rejects
// requests that present no credentials -- either by demanding a client
// certificate, or with HTTP 401 on at least one of unauthProbePaths and no
// success status on any of them.
func AssessTLSService(addr string, port uint16, timeout time.Duration) TLSAssessment {
	var a TLSAssessment
	hostPort := net.JoinHostPort(addr, strconv.Itoa(int(port)))

	// "+" runs the script even where its port rule would not, since EVE-k
	// services sit on ports nmap does not associate with TLS.
	run, err := runNmap(2*timeout, "-Pn", "-n", "-sT", "-p", strconv.Itoa(int(port)),
		"--script", "+ssl-enum-ciphers", "--script-timeout", timeout.String(), addr)
	if err != nil {
		a.Problems = append(a.Problems, err.Error())
	} else {
		for _, host := range run.Hosts {
			for _, p := range host.Ports {
				for _, script := range p.Scripts {
					if script.ID != "ssl-enum-ciphers" {
						continue
					}
					for _, table := range script.Tables {
						a.Protocols = append(a.Protocols, table.Key)
					}
					for _, elem := range script.Elems {
						if elem.Key == "least strength" {
							a.LeastStrength = elem.Value
						}
					}
				}
			}
		}
		if len(a.Protocols) == 0 {
			a.Problems = append(a.Problems, "no TLS handshake succeeded")
		}
		for _, proto := range a.Protocols {
			if proto != "TLSv1.2" && proto != "TLSv1.3" {
				a.Problems = append(a.Problems, "accepts "+proto)
			}
		}
		if len(a.Protocols) > 0 && a.LeastStrength != "A" {
			a.Problems = append(a.Problems,
				fmt.Sprintf("weakest cipher graded %q", a.LeastStrength))
		}
	}

	a.PlaintextStatus = plaintextHTTPStatus(hostPort, timeout)
	if a.PlaintextStatus != 0 && a.PlaintextStatus < 400 {
		a.Problems = append(a.Problems,
			fmt.Sprintf("answers plaintext HTTP with status %d", a.PlaintextStatus))
	}

	var certRequested bool
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// The probe carries no credentials, and the device's
				// certificate chains to a cluster CA the test does not have.
				InsecureSkipVerify: true, //nolint:gosec
				GetClientCertificate: func(*tls.CertificateRequestInfo) (
					*tls.Certificate, error) {
					certRequested = true
					return &tls.Certificate{}, nil
				},
			},
		},
	}
	a.UnauthStatus = make(map[string]int)
	for _, path := range unauthProbePaths {
		resp, err := client.Get("https://" + hostPort + path)
		if err != nil {
			if certRequested {
				a.ClientCertRequired = true
				return a
			}
			a.Problems = append(a.Problems,
				fmt.Sprintf("unauthenticated HTTPS request for %s failed without a "+
					"client certificate being demanded: %v", path, err))
			continue
		}
		_ = resp.Body.Close()
		a.UnauthStatus[path] = resp.StatusCode
		if resp.StatusCode < 400 {
			a.Problems = append(a.Problems,
				fmt.Sprintf("unauthenticated HTTPS request for %s answered with "+
					"status %d", path, resp.StatusCode))
		}
	}
	var rejected bool
	for _, status := range a.UnauthStatus {
		rejected = rejected || status == http.StatusUnauthorized
	}
	if len(a.UnauthStatus) > 0 && !rejected {
		a.Problems = append(a.Problems,
			fmt.Sprintf("no unauthenticated HTTPS request answered with status %d: %v",
				http.StatusUnauthorized, a.UnauthStatus))
	}
	return a
}

// SSHAuthMethods returns the authentication methods the SSH server at addr
// offers, as reported by nmap's ssh-auth-methods script. The script sends
// no credentials: it asks for authentication method "none", and the server's
// refusal lists the methods it would accept.
func SSHAuthMethods(addr string, timeout time.Duration) ([]string, error) {
	run, err := runNmap(2*timeout, "-Pn", "-n", "-sT", "-p", strconv.Itoa(SSHPort),
		"--script", "ssh-auth-methods", "--script-args", "ssh.user=evetest-probe",
		"--script-timeout", timeout.String(), addr)
	if err != nil {
		return nil, err
	}
	for _, host := range run.Hosts {
		for _, p := range host.Ports {
			for _, script := range p.Scripts {
				if script.ID != "ssh-auth-methods" {
					continue
				}
				for _, table := range script.Tables {
					if table.Key != "Supported authentication methods" {
						continue
					}
					var methods []string
					for _, elem := range table.Elems {
						methods = append(methods, elem.Value)
					}
					return methods, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("ssh-auth-methods reported no authentication methods")
}

// plaintextHTTPStatus sends a plaintext HTTP request to hostPort and returns
// the response status, or 0 if the service did not answer with HTTP. A Go
// TLS server answers such a request with 400, which counts as a refusal.
func plaintextHTTPStatus(hostPort string, timeout time.Duration) int {
	conn, err := net.DialTimeout("tcp", hostPort, timeout)
	if err != nil {
		return 0
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("GET / HTTP/1.0\r\n\r\n")); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// Violations logs every port in ports and returns each way they fall short:
// every open UDP port, since it cannot be HTTPS, an SSH server offering any
// authentication method but publickey, and every problem AssessTLSService
// finds on any other open TCP port.
func Violations(ports []OpenPort) []string {
	log := evetest.Logger()
	var failures []string
	for _, p := range ports {
		switch {
		case p.Protocol == "udp":
			failures = append(failures, p.String()+": open UDP port")
		case p.Port == SSHPort:
			methods, err := SSHAuthMethods(p.Addr, 30*time.Second)
			log.Infof("SSH authentication methods of %v: %v", p, methods)
			switch {
			case err != nil:
				failures = append(failures, p.String()+": "+err.Error())
			case len(methods) != 1 || methods[0] != "publickey":
				failures = append(failures, fmt.Sprintf(
					"%v: offers SSH authentication methods %v, want only publickey",
					p, methods))
			}
		default:
			assessment := AssessTLSService(p.Addr, p.Port, 30*time.Second)
			log.Infof("TLS assessment of %v: %v", p, assessment)
			for _, problem := range assessment.Problems {
				failures = append(failures, p.String()+": "+problem)
			}
		}
	}
	return failures
}

// Reached reports whether ports shows SSHPort open on addr, which proves a
// scan of addr got through to the device.
func Reached(ports []OpenPort, addr string) bool {
	for _, p := range ports {
		if p.Addr == addr && p.Protocol == "tcp" && p.Port == SSHPort {
			return true
		}
	}
	return false
}
