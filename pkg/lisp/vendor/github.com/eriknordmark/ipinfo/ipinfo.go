// Package ipinfo provides info on IP address location
// using the http://ipinfo.io service.
package ipinfo

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

var ipinfoURI = "http://ipinfo.io"

// IPInfo wraps json response
type IPInfo struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
	City     string `json:"city"`
	Region   string `json:"region"`
	Country  string `json:"country"`
	Loc      string `json:"loc"`
	Org      string `json:"org"`
	Postal   string `json:"postal"`
}

type Options struct {
	Timeout  time.Duration
	SourceIp net.IP
	Token    string
}

// MyIP provides information about the public IP address of the client.
func MyIP() (*IPInfo, error) {
	return getInfo(fmt.Sprintf("%s/json", ipinfoURI), nil)
}

// ForeignIP provides information about the given IP address (IPv4 or IPv6)
func ForeignIP(ip string) (*IPInfo, error) {
	return getInfo(fmt.Sprintf("%s/%s/json", ipinfoURI, ip), nil)
}

// MyIP provides information about the public IP address of the client.
func MyIPWithOptions(opt Options) (*IPInfo, error) {
	return getInfo(fmt.Sprintf("%s/json", ipinfoURI), &opt)
}

// Undercover code that makes the real call to the webservice
func getInfo(url string, opt *Options) (*IPInfo, error) {
	var localAddr net.IP
	if opt != nil {
		localAddr = opt.SourceIp
		if opt.Token != "" {
			url += fmt.Sprintf("/?token=%s", opt.Token)
		}
	}
	localTCPAddr := net.TCPAddr{IP: localAddr}
	d := net.Dialer{LocalAddr: &localTCPAddr}
	if opt != nil && opt.Timeout != 0 {
		d.Timeout = opt.Timeout
	}
	transport := &http.Transport{
		Dial:  d.Dial,
		Proxy: http.ProxyFromEnvironment,
	}
	client := &http.Client{Transport: transport}
	if opt != nil && opt.Timeout != 0 {
		client.Timeout = opt.Timeout
	}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	switch response.StatusCode {
	case http.StatusOK:
		var ipinfo IPInfo
		err = json.NewDecoder(response.Body).Decode(&ipinfo)
		if err != nil {
			return nil, err
		}
		return &ipinfo, nil
	default:
		errStr := fmt.Sprintf("%s got statuscode %d %s body <%v>",
			url, response.StatusCode,
			http.StatusText(response.StatusCode), response.Body)
		return nil, errors.New(errStr)
	}
}
