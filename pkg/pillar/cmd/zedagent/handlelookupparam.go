// Copyright (c) 2017-2018 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// Publish the IsZedmanager AppNetworkConfig and /etc/hosts
// XXX Should also look at the corresponding AppNetworkStatus and report
// any errors back as device errors to zedcloud.

package zedagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"time"

	"github.com/eriknordmark/ipinfo"
	zconfig "github.com/lf-edge/eve/api/go/config"
	"github.com/lf-edge/eve/pkg/pillar/cmd/tpmmgr"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/lf-edge/eve/pkg/pillar/zedcloud"
	log "github.com/sirupsen/logrus"
)

const (
	infraFileName           = identityDirname + "/infra"
	zedserverConfigFileName = tmpDirname + "/zedserverconfig"
)

// This is local to handlelookupparam. Used to determine any changes in
// the device/mgmt LISP config.
type DeviceLispConfig struct {
	MapServers      []types.MapServer
	LispInstance    uint32
	EID             net.IP
	DnsNameToIPList []types.DnsNameToIP
	ClientAddr      string // To detect NATs
}

// Assumes the config files are in identityDirname, which is /config. Files are:
//  device.cert.pem,
//  device.key.pem		Device certificate/key created before this
//  		     		client is started.
//  infra			If this file exists assume zedcontrol and do not
//  				create ACLs
//  root-certificate.pem	Root CA cert(s)
//
//  In addition we have:
//  /var/tmp/zededa/zedserverconfig Written by us; zed server EIDs
//  /var/tmp/zededa/uuid	Written by us
//
var lispPrevConfigHash []byte
var prevLispConfig DeviceLispConfig

func handleLookupParam(getconfigCtx *getconfigContext,
	devConfig *zconfig.EdgeDevConfig) {

	// XXX should we handle changes at all? Want to update zedserverconfig
	// and eids for ACLs.

	//Fill DeviceLispConfig struct with LispInfo config...
	var lispConfig = DeviceLispConfig{}

	log.Debugf("handleLookupParam got config %v\n", devConfig)
	lispInfo := devConfig.LispInfo
	if lispInfo == nil {
		log.Errorf("handleLookupParam: missing lispInfo\n")
		return
	}
	configHash := computeConfigSha(lispInfo)
	same := bytes.Equal(configHash, lispPrevConfigHash)
	lispPrevConfigHash = configHash

	if same {
		// We normally don't hit this since the order in
		// the DnsNameToIPList from the proto.Encode is random.
		// Hence we check again after sorting.
		log.Debugf("handleLookupParam: lispInfo sha is unchanged\n")
		return
	}
	lispConfig.LispInstance = lispInfo.LispInstance
	lispConfig.EID = net.ParseIP(lispInfo.EID)
	lispConfig.ClientAddr = lispInfo.ClientAddr
	lispConfig.MapServers = make([]types.MapServer, len(lispInfo.LispMapServers))
	var lmsx int = 0
	for _, lms := range lispInfo.LispMapServers {

		mapServer := new(types.MapServer)
		mapServer.ServiceType = types.MST_MAPSERVER
		mapServer.NameOrIp = lms.NameOrIp
		mapServer.Credential = lms.Credential
		lispConfig.MapServers[lmsx] = *mapServer
		lmsx++
	}
	lispConfig.DnsNameToIPList = make([]types.DnsNameToIP,
		len(lispInfo.ZedServers)+len(lispInfo.Dns))
	var zsx int = 0
	for _, zs := range lispInfo.ZedServers {

		nameToIP := new(types.DnsNameToIP)
		nameToIP.HostName = zs.HostName
		nameToIP.IPs = make([]net.IP, len(zs.EID))
		for i, ip := range zs.EID {
			nameToIP.IPs[i] = net.ParseIP(ip)
		}
		lispConfig.DnsNameToIPList[zsx] = *nameToIP
		zsx++
	}
	for _, dn := range lispInfo.Dns {

		nameToIP := new(types.DnsNameToIP)
		nameToIP.HostName = dn.HostName
		nameToIP.IPs = make([]net.IP, len(dn.Address))
		for i, ip := range dn.Address {
			nameToIP.IPs[i] = net.ParseIP(ip)
		}
		lispConfig.DnsNameToIPList[zsx] = *nameToIP
		zsx++
	}

	// compare lispConfig against a prevLispConfig
	sort.Slice(lispConfig.DnsNameToIPList[:],
		func(i, j int) bool {
			return lispConfig.DnsNameToIPList[i].HostName <
				lispConfig.DnsNameToIPList[j].HostName
		})
	if reflect.DeepEqual(prevLispConfig, lispConfig) {
		log.Debugf("handleLookupParam: sorted lispInfo is unchanged\n")
		return
	}
	prevLispConfig = lispConfig

	log.Infof("handleLookupParam: updated lispInfo %v\n", lispInfo)

	deviceCert, err := zedcloud.GetClientCert()
	if err != nil {
		log.Fatal(err)
	}

	ACLPromisc := false
	if _, err := os.Stat(infraFileName); err == nil {
		log.Debugf("Setting ACLPromisc\n")
		ACLPromisc = true
	}

	var addInfoDevice *types.AdditionalInfoDevice
	// Determine location information and use as AdditionalInfo
	opt := ipinfo.Options{Timeout: 5 * time.Second}
	if myIP, err := ipinfo.MyIPWithOptions(opt); err == nil {
		addInfo := types.AdditionalInfoDevice{
			UnderlayIP: myIP.IP,
			Hostname:   myIP.Hostname,
			City:       myIP.City,
			Region:     myIP.Region,
			Country:    myIP.Country,
			Loc:        myIP.Loc,
			Org:        myIP.Org,
		}
		addInfoDevice = &addInfo
	}

	// If we got a StatusNotFound the EID will be zero
	if lispConfig.EID == nil {
		log.Errorf("Did not receive an EID\n")
		os.Remove(zedserverConfigFileName)
		return
	}

	// Convert from IID and IPv6 EID to a string with
	// [iid]eid, where the eid uses the textual format defined in
	// RFC 5952. The iid is printed as an integer.
	sigdata := fmt.Sprintf("[%d]%s",
		lispConfig.LispInstance, lispConfig.EID.String())
	log.Debugf("sigdata (len %d) %s\n", len(sigdata), sigdata)

	hasher := sha256.New()
	hasher.Write([]byte(sigdata))
	hash := hasher.Sum(nil)
	log.Debugf("hash (len %d) % x\n", len(hash), hash)
	log.Debugf("base64 hash %s\n",
		base64.StdEncoding.EncodeToString(hash))
	var signature string
	switch key := deviceCert.PrivateKey.(type) {
	default:
		log.Fatal("Private Key RSA type not supported")
	case zedcloud.TpmPrivateKey:
		r, s, err := tpmmgr.TpmSign(hash)
		if err != nil {
			log.Fatal("zedcloud.Sign: ", err)
		}
		log.Debugf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres := r.Bytes()
		sigres = append(sigres, s.Bytes()...)
		signature = base64.StdEncoding.EncodeToString(sigres)
		log.Debugf("sigres (len %d): % x\n",
			len(sigres), sigres)
		log.Debugln("signature:", signature)
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hash)
		if err != nil {
			log.Fatal("ecdsa.Sign: ", err)
		}
		log.Debugf("r.bytes %d s.bytes %d\n", len(r.Bytes()),
			len(s.Bytes()))
		sigres := r.Bytes()
		sigres = append(sigres, s.Bytes()...)
		signature = base64.StdEncoding.EncodeToString(sigres)
		log.Debugf("sigres (len %d): % x\n",
			len(sigres), sigres)
		log.Debugln("signature:", signature)
	}
	log.Debugf("MapServers %+v\n", lispConfig.MapServers)
	log.Debugf("Lisp IID %d\n", lispConfig.LispInstance)
	log.Debugf("EID %s\n", lispConfig.EID)

	// write zedserverconfig file with hostname to EID mappings
	f, err := os.Create(zedserverConfigFileName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	for _, ne := range lispConfig.DnsNameToIPList {
		for _, ip := range ne.IPs {
			output := fmt.Sprintf("%-46v %s\n",
				ip, ne.HostName)
			_, err := f.WriteString(output)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	f.Sync()

	// Determine whether NAT is in use
	if publicIP, err := addrStringToIP(lispConfig.ClientAddr); err != nil {
		log.Errorf("Failed to convert %s, error %s\n",
			lispConfig.ClientAddr, err)
	} else {
		nat := !IsMyAddress(publicIP)
		log.Infof("NAT %v, publicIP %v\n", nat, publicIP)
	}

	// Write an AppNetworkConfig for the ZedManager application
	uv := types.UUIDandVersion{
		UUID:    devUUID,
		Version: devConfig.Id.String(),
	}
	config := types.AppNetworkConfig{
		UUIDandVersion: uv,
		DisplayName:    "zedmanager",
		IsZedmanager:   true,
		Activate:       true,
		// Experimental flag from protobuf is re-interpreted to mean
		// using legacy data plane (i.e. lispers.net)
		LegacyDataPlane: lispInfo.Experimental,
	}

	olconf := make([]types.OverlayNetworkConfig, 1)
	config.OverlayNetworkList = olconf
	olconf[0].EID = lispConfig.EID
	olconf[0].LispSignature = signature
	olconf[0].AdditionalInfoDevice = addInfoDevice
	olconf[0].MgmtIID = lispConfig.LispInstance
	olconf[0].MgmtDnsNameToIPList = lispConfig.DnsNameToIPList
	olconf[0].MgmtMapServers = lispConfig.MapServers
	acl := make([]types.ACE, 1)
	olconf[0].ACLs = acl
	matches := make([]types.ACEMatch, 1)
	acl[0].Matches = matches
	actions := make([]types.ACEAction, 1)
	acl[0].Actions = actions
	if ACLPromisc {
		matches[0].Type = "ip"
		matches[0].Value = "::/0"
	} else {
		matches[0].Type = "eidset"
	}
	publishAppNetworkConfig(getconfigCtx, config)

	// Add DnsNameToIPList to /etc/hosts
	cmd := exec.Command("/opt/zededa/bin/handlezedserverconfig.sh")
	stdout, err := cmd.Output()
	if err != nil {
		log.Errorln(err.Error())
	}
	log.Debugf("handlezedserverconfig output %s\n", stdout)
}

func publishAppNetworkConfig(getconfigCtx *getconfigContext,
	config types.AppNetworkConfig) {

	key := config.Key()
	log.Debugf("publishAppNetworkConfig %s\n", key)
	pub := getconfigCtx.pubAppNetworkConfig
	pub.Publish(key, config)
}

func unpublishAppNetworkConfig(getconfigCtx *getconfigContext, key string) {

	log.Debugf("unpublishAppNetworkConfig %s\n", key)
	pub := getconfigCtx.pubAppNetworkConfig
	c, _ := pub.Get(key)
	if c == nil {
		log.Errorf("unpublishAppNetworkConfig(%s) not found\n", key)
		return
	}
	pub.Unpublish(key)
}

func addrStringToIP(addrString string) (net.IP, error) {
	clientTCP, err := net.ResolveTCPAddr("tcp", addrString)
	if err != nil {
		return net.IP{}, err
	}
	return clientTCP.IP, nil
}

// IsMyAddress checks the IP address against the local IPs. Returns True if
// there is a match.
func IsMyAddress(clientIP net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok &&
			!ipnet.IP.IsLoopback() {
			if bytes.Compare(ipnet.IP, clientIP) == 0 {
				return true
			}
		}
	}
	return false
}
