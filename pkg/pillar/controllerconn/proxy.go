// Copyright (c) 2017-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package controllerconn

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedpac"
)

// ProxyConfig holds configuration for HTTP proxy settings. See
// FromEnvironment for details.
type ProxyConfig struct {
	// HTTPProxy represents the value of the HTTP_PROXY or
	// http_proxy environment variable. It will be used as the proxy
	// URL for HTTP requests and HTTPS requests unless overridden by
	// HTTPSProxy or NoProxy.
	HTTPProxy string

	// HTTPSProxy represents the HTTPS_PROXY or https_proxy
	// environment variable. It will be used as the proxy URL for
	// HTTPS requests unless overridden by NoProxy.
	HTTPSProxy string

	// NoProxy represents the NO_PROXY or no_proxy environment
	// variable. It specifies a string that contains comma-separated values
	// specifying hosts that should be excluded from proxying. Each value is
	// represented by an IP address prefix (1.2.3.4), an IP address prefix in
	// CIDR notation (1.2.3.4/8), a domain name, or a special DNS label (*).
	// An IP address prefix and domain name can also include a literal port
	// number (1.2.3.4:80).
	// A domain name matches that name and all subdomains. A domain name with
	// a leading "." matches subdomains only. For example "foo.com" matches
	// "foo.com" and "bar.foo.com"; ".y.com" matches "x.y.com" but not "y.com".
	// A single asterisk (*) indicates that no proxying should be done.
	// A best effort is made to parse the string and errors are
	// ignored.
	NoProxy string

	// CGI holds whether the current process is running
	// as a CGI handler (FromEnvironment infers this from the
	// presence of a REQUEST_METHOD environment variable).
	// When this is set, ProxyForURL will return an error
	// when HTTPProxy applies, because a client could be
	// setting HTTP_PROXY maliciously. See https://golang.org/s/cgihttpproxy.
	CGI bool
}

// ProxyFunc returns a function that determines the proxy URL to use for
// a given request URL. Changing the contents of cfg will not affect
// proxy functions created earlier.
//
// A nil URL and nil error are returned if no proxy is defined in the
// environment, or a proxy should not be used for the given request, as
// defined by NO_PROXY.
//
// As a special case, if req.URL.Host is "localhost" (with or without a
// port number), then a nil URL and nil error will be returned.
func (cfg *ProxyConfig) ProxyFunc() func(reqURL *url.URL) (*url.URL, error) {
	// Preprocess the ProxyConfig settings for more efficient evaluation.
	handler := &proxyHandler{
		ProxyConfig: *cfg,
	}
	handler.init()
	return handler.proxyForURL
}

// proxyHandler handles HTTP proxying based on the parsed configuration.
type proxyHandler struct {
	// Config represents the original configuration as defined above.
	ProxyConfig

	// httpsProxy is the parsed URL of the HTTPSProxy if defined.
	httpsProxy *url.URL

	// httpProxy is the parsed URL of the HTTPProxy if defined.
	httpProxy *url.URL

	// ipMatchers represent all values in the NoProxy that are IP address
	// prefixes or an IP address in CIDR notation.
	ipMatchers []matcher

	// domainMatchers represent all values in the NoProxy that are a domain
	// name or hostname & domain name
	domainMatchers []matcher
}

func (h *proxyHandler) proxyForURL(reqURL *url.URL) (*url.URL, error) {
	var proxy *url.URL
	// since ws and wss use the same port numbers as http and https, send ws and wss
	// to the same proxy configured makes sense
	switch reqURL.Scheme {
	case "https", "wss":
		proxy = h.httpsProxy
	case "http", "ws":
		proxy = h.httpProxy
	}
	if proxy == nil {
		return nil, nil
	}
	if !h.useProxy(canonicalAddr(reqURL)) {
		return nil, nil
	}

	return proxy, nil
}

func (h *proxyHandler) parseProxy(proxy string) (*url.URL, error) {
	if proxy == "" {
		return nil, nil
	}

	proxyURL, err := url.Parse(proxy)
	if err != nil ||
		(proxyURL.Scheme != "http" &&
			proxyURL.Scheme != "https" &&
			proxyURL.Scheme != "socks5") {
		// proxy was bogus. Try prepending "http://" to it and
		// see if that parses correctly. If not, we fall
		// through and complain about the original one.
		if proxyURL, err := url.Parse("http://" + proxy); err == nil {
			return proxyURL, nil
		}
	}
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %v", proxy, err)
	}
	return proxyURL, nil
}

// useProxy reports whether requests to addr should use a proxy,
// according to the NO_PROXY or no_proxy environment variable.
// addr is always a canonicalAddr with a host and port.
func (h *proxyHandler) useProxy(addr string) bool {
	if len(addr) == 0 {
		return true
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return false
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() {
			return false
		}
	}

	addr = strings.ToLower(strings.TrimSpace(host))

	if ip != nil {
		for _, m := range h.ipMatchers {
			if m.match(addr, port, ip) {
				return false
			}
		}
	}
	for _, m := range h.domainMatchers {
		if m.match(addr, port, ip) {
			return false
		}
	}
	return true
}

func (h *proxyHandler) init() {
	if parsed, err := h.parseProxy(h.HTTPProxy); err == nil {
		h.httpProxy = parsed
	}
	if parsed, err := h.parseProxy(h.HTTPSProxy); err == nil {
		h.httpsProxy = parsed
	}

	for _, p := range strings.Split(h.NoProxy, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if len(p) == 0 {
			continue
		}

		if p == "*" {
			h.ipMatchers = []matcher{allMatch{}}
			h.domainMatchers = []matcher{allMatch{}}
			return
		}

		// IPv4/CIDR, IPv6/CIDR
		if _, pnet, err := net.ParseCIDR(p); err == nil {
			h.ipMatchers = append(h.ipMatchers, cidrMatch{cidr: pnet})
			continue
		}

		// IPv4:port, [IPv6]:port
		phost, pport, err := net.SplitHostPort(p)
		if err == nil {
			if len(phost) == 0 {
				// There is no host part, likely the entry is malformed; ignore.
				continue
			}
			if phost[0] == '[' && phost[len(phost)-1] == ']' {
				phost = phost[1 : len(phost)-1]
			}
		} else {
			phost = p
		}
		// IPv4, IPv6
		if pip := net.ParseIP(phost); pip != nil {
			h.ipMatchers = append(h.ipMatchers, ipMatch{ip: pip, port: pport})
			continue
		}

		if len(phost) == 0 {
			// There is no host part, likely the entry is malformed; ignore.
			continue
		}

		// domain.com or domain.com:80
		// foo.com matches bar.foo.com
		// .domain.com or .domain.com:port
		// *.domain.com or *.domain.com:port
		if strings.HasPrefix(phost, "*.") {
			phost = phost[1:]
		}
		matchHost := false
		if phost[0] != '.' {
			matchHost = true
			phost = "." + phost
		}
		h.domainMatchers = append(h.domainMatchers,
			domainMatch{host: phost, port: pport, matchHost: matchHost})
	}
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

// canonicalAddr returns url.Host but always with a ":port" suffix
func canonicalAddr(url *url.URL) string {
	addr := url.Hostname()
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(addr, port)
}

// matcher represents the matching rule for a given value in the NO_PROXY list
type matcher interface {
	// match returns true if the host and optional port or ip and optional port
	// are allowed
	match(host, port string, ip net.IP) bool
}

// allMatch matches on all possible inputs
type allMatch struct{}

func (a allMatch) match(host, port string, ip net.IP) bool {
	return true
}

type cidrMatch struct {
	cidr *net.IPNet
}

func (m cidrMatch) match(host, port string, ip net.IP) bool {
	return m.cidr.Contains(ip)
}

type ipMatch struct {
	ip   net.IP
	port string
}

func (m ipMatch) match(host, port string, ip net.IP) bool {
	if m.ip.Equal(ip) {
		return m.port == "" || m.port == port
	}
	return false
}

type domainMatch struct {
	host string
	port string

	matchHost bool
}

func (m domainMatch) match(host, port string, ip net.IP) bool {
	if strings.HasSuffix(host, m.host) || (m.matchHost && host == m.host[1:]) {
		return m.port == "" || m.port == port
	}
	return false
}

// IsProxyConfigEmpty returns true if proxy is not configured.
func IsProxyConfigEmpty(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) == 0 &&
		len(proxyConfig.ProxyCertPEM) == 0 &&
		proxyConfig.Exceptions == "" &&
		proxyConfig.Pacfile == "" &&
		proxyConfig.NetworkProxyEnable == false &&
		proxyConfig.NetworkProxyURL == "" {
		return true
	}
	return false
}

// IsExplicitProxyConfigured returns true if EVE is explicitly configured
// to route traffic via a proxy for a given uplink interface.
func IsExplicitProxyConfigured(proxyConfig types.ProxyConfig) bool {
	if len(proxyConfig.Proxies) > 0 ||
		proxyConfig.Pacfile != "" ||
		proxyConfig.NetworkProxyEnable {
		return true
	}
	return false
}

// LookupProxy determines the proxy URL to use for accessing a given raw URL
// through a specific network interface. It looks up the proxy configuration
// associated with the interface in the provided DeviceNetworkStatus.
// If a PAC file is configured, it evaluates it to find the proxy.
// Otherwise, it uses statically configured proxy settings.
// Returns the proxy URL to use, or nil if direct connection should be used.
func LookupProxy(log *base.LogObject, status *types.DeviceNetworkStatus, ifname string,
	rawURL string) (*url.URL, error) {

	for _, port := range status.Ports {
		log.Tracef("LookupProxy: Looking for proxy config on port %s",
			port.IfName)
		if port.IfName != ifname {
			continue
		}
		log.Tracef("LookupProxy: Port configuration found for %s", ifname)
		proxyConfig := port.ProxyConfig

		// Check if the URL is present in exception list
		// XXX Should we just get the domain name part of URL and compare?
		// XXX Doing the domain portion comparison for now.
		// Parse url and find the host domain part
		u, err := url.Parse(rawURL)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: malformed URL %s", rawURL)
			log.Error(errStr)
			return nil, errors.New(errStr)
		}

		// Check if we have a PAC file
		if len(proxyConfig.Pacfile) > 0 {
			pacFile, err := base64.StdEncoding.DecodeString(proxyConfig.Pacfile)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: Decoding proxy file failed: %s", err)
				log.Error(errStr)
				return nil, errors.New(errStr)
			}
			proxyString, err := zedpac.Find_proxy_sync(
				string(pacFile), rawURL, u.Host)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file could not find proxy for %s: %s",
					rawURL, err)
				log.Error(errStr)
				return nil, errors.New(errStr)
			}
			//if proxyString == "DIRECT" {
			if strings.HasPrefix(proxyString, "DIRECT") {
				return nil, nil
			}
			proxies := strings.Split(proxyString, ";")
			if len(proxies) == 0 {
				log.Error("LookupProxy: Number of proxies in PAC file result is Zero")
				return nil, nil
			}

			// XXX Take the first proxy for now. Failing over to the next
			// proxy should be implemented
			proxy0 := proxies[0]
			proxy0 = strings.Split(proxy0, " ")[1]
			// Proxy address returned by PAC does not have the URL scheme.
			// We prepend the scheme (http/https) of the incoming raw URL.
			proxy0 = "http://" + proxy0
			proxy, err := url.Parse(proxy0)
			if err != nil {
				errStr := fmt.Sprintf("LookupProxy: PAC file returned invalid proxy %s: %s",
					proxyString, err)
				log.Error(errStr)
				return nil, errors.New(errStr)
			}
			log.Tracef("LookupProxy: PAC proxy being used is %s", proxy0)
			return proxy, err
		}

		config := &ProxyConfig{}
		for _, proxy := range proxyConfig.Proxies {
			switch proxy.Type {
			case types.NetworkProxyTypeHTTP:
				var httpProxy string
				if proxy.Port > 0 {
					httpProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPProxy = httpProxy
				log.Tracef("LookupProxy: Adding HTTP proxy %s for port %s",
					config.HTTPProxy, ifname)
			case types.NetworkProxyTypeHTTPS:
				var httpsProxy string
				if proxy.Port > 0 {
					httpsProxy = fmt.Sprintf("%s:%d", proxy.Server, proxy.Port)
				} else {
					httpsProxy = fmt.Sprintf("%s", proxy.Server)
				}
				config.HTTPSProxy = httpsProxy
				log.Tracef("LookupProxy: Adding HTTPS proxy %s for port %s",
					config.HTTPSProxy, ifname)
			default:
				// XXX We should take care of Socks proxy, FTP proxy also in future
			}
		}
		config.NoProxy = proxyConfig.Exceptions
		proxyFunc := config.ProxyFunc()
		proxy, err := proxyFunc(u)
		if err != nil {
			errStr := fmt.Sprintf("LookupProxy: proxyFunc error: %s", err)
			log.Error(errStr)
			return proxy, errors.New(errStr)
		}
		return proxy, err
	}
	log.Functionf("LookupProxy: No proxy configured for port %s", ifname)
	return nil, nil
}

// IntfLookupProxyCfg - check if the intf has proxy configured
func IntfLookupProxyCfg(log *base.LogObject, status *types.DeviceNetworkStatus, ifname,
	downloadURL string, trType zedUpload.SyncTransportType) string {
	// if proxy is not on the intf, then don't change anything
	// if download URL has "http://" or "https://" then no change here regardless of proxy
	// if there is proxy on this intf, treat empty url scheme as for https or http but prefer https,
	// replace the passed-in download-url scheme "docker://" and maybe "sftp://" later, to https
	// XXX for sftp, currently the FQDN can not have scheme attached, but url.Parse will fail without it
	if !strings.Contains(downloadURL, "://") {
		switch trType {
		case zedUpload.SyncSftpTr:
			downloadURL = "http://" + downloadURL
		case zedUpload.SyncOCIRegistryTr, zedUpload.SyncHttpTr:
			downloadURL = "https://" + downloadURL
		default:
			downloadURL = "https://" + downloadURL
		}
	}
	passURL, err := url.Parse(downloadURL)
	if err != nil {
		return downloadURL
	}

	switch passURL.Scheme {
	case "http", "https":
		return downloadURL
	}

	tmpURL := passURL
	tmpURL.Scheme = "https"
	proxyURL, err := LookupProxy(log, status, ifname, tmpURL.String())
	if err == nil && proxyURL != nil {
		return tmpURL.String()
	}
	tmpURL.Scheme = "http"
	proxyURL, err = LookupProxy(log, status, ifname, tmpURL.String())
	if err == nil && proxyURL != nil {
		return tmpURL.String()
	}

	return downloadURL
}

// CheckAndGetNetworkProxy fetches the PAC file and WPAD URL for the given network port,
// if configured, and stores the proxy settings in the corresponding NetworkPortStatus.
func CheckAndGetNetworkProxy(log *base.LogObject, dns *types.DeviceNetworkStatus,
	ifname string, metrics *AgentMetrics) error {

	portStatus := dns.LookupPortByIfName(ifname)
	if portStatus == nil {
		errStr := fmt.Sprintf("Missing port status for interface %s", ifname)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	proxyConfig := &portStatus.ProxyConfig

	log.Tracef("CheckAndGetNetworkProxy(%s): enable %v, url %s\n",
		ifname, proxyConfig.NetworkProxyEnable,
		proxyConfig.NetworkProxyURL)

	if proxyConfig.Pacfile != "" {
		log.Tracef("CheckAndGetNetworkProxy(%s): already have Pacfile\n",
			ifname)
		return nil
	}
	if !proxyConfig.NetworkProxyEnable {
		log.Tracef("CheckAndGetNetworkProxy(%s): not enabled\n",
			ifname)
		return nil
	}
	if proxyConfig.NetworkProxyURL != "" {
		pac, err := getPacFile(log, proxyConfig.NetworkProxyURL, dns, ifname, metrics)
		if err != nil {
			errStr := fmt.Sprintf("Failed to fetch %s for %s: %s",
				proxyConfig.NetworkProxyURL, ifname, err)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		proxyConfig.Pacfile = pac
		return nil
	}
	dn := portStatus.DomainName
	if dn == "" {
		errStr := fmt.Sprintf("NetworkProxyEnable for %s but neither a NetworkProxyURL nor a DomainName",
			ifname)
		log.Errorln(errStr)
		return errors.New(errStr)
	}
	log.Functionf("CheckAndGetNetworkProxy(%s): DomainName %s\n",
		ifname, dn)
	// Try http://wpad.%s/wpad.dat", dn where we the leading labels
	// in DomainName until we succeed
	for {
		url := fmt.Sprintf("http://wpad.%s/wpad.dat", dn)
		pac, err := getPacFile(log, url, dns, ifname, metrics)
		if err == nil {
			proxyConfig.Pacfile = pac
			proxyConfig.WpadURL = url
			return nil
		}
		errStr := fmt.Sprintf("Failed to fetch %s for %s: %s",
			url, ifname, err)
		log.Warnln(errStr)
		i := strings.Index(dn, ".")
		if i == -1 {
			log.Functionf("CheckAndGetNetworkProxy(%s): no dots in DomainName %s\n",
				ifname, dn)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
		b := []byte(dn)
		dn = string(b[i+1:])
		// How many dots left? End when we have a TLD i.e., no dots
		// since wpad.com isn't a useful place to look
		count := strings.Count(dn, ".")
		if count == 0 {
			log.Functionf("CheckAndGetNetworkProxy(%s): reached TLD in DomainName %s\n",
				ifname, dn)
			log.Errorln(errStr)
			return errors.New(errStr)
		}
	}
}

func getPacFile(log *base.LogObject, url string, dns *types.DeviceNetworkStatus,
	ifname string, metrics *AgentMetrics) (string, error) {

	client := NewClient(log, ClientOptions{
		NetworkSendTimeout:  15 * time.Second,
		AgentName:           "wpad",
		AgentMetrics:        metrics,
		DeviceNetworkStatus: dns,
	})
	// Avoid using a proxy to fetch the wpad.dat; 15 second timeout
	rv, err := client.SendOnIntf(
		context.Background(), url, ifname, nil, RequestOptions{})
	if err != nil {
		return "", err
	}
	contentType := rv.HTTPResp.Header.Get("Content-Type")
	if contentType == "" {
		errStr := fmt.Sprintf("%s no content-type\n", url)
		return "", errors.New(errStr)
	}
	mimeType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		errStr := fmt.Sprintf("%s ParseMediaType failed %v\n", url, err)
		return "", errors.New(errStr)
	}
	switch mimeType {
	case "application/x-ns-proxy-autoconfig":
		log.Functionf("getPacFile(%s): fetched from URL %s: %s\n",
			ifname, url, string(rv.RespContents))
		encoded := base64.StdEncoding.EncodeToString(rv.RespContents)
		return encoded, nil
	default:
		errStr := fmt.Sprintf("Incorrect mime-type %s from %s",
			mimeType, url)
		return "", errors.New(errStr)
	}
}
