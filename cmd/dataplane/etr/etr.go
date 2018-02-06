package etr

import (
	"fmt"
	"log"
	"net"
	"bytes"
	"syscall"
	"io/ioutil"
	"encoding/json"
	"crypto/aes"
	"crypto/cipher"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	"github.com/zededa/go-provision/types"
	"github.com/zededa/go-provision/dataplane/fib"
)

const uplinkFileName = "/var/tmp/zedrouter/config/global"

func StartETR(ephPort int) (*net.UDPConn, *pfring.Ring, int, int) {
	log.Println("Starting ETR thread on port 4341")
	log.Printf("Starting ETR thread on ephemeral port %d\n", ephPort)

	// create a udp server socket and start listening on port 4341
	// XXX Using ipv4 underlay for now. Will have to figure out v6 underlay case.
	etrServer, err := net.ResolveUDPAddr("udp4", ":4341")
	if err != nil {
		log.Printf("Error resolving ETR socket address: %s\n", err)
		return nil, nil, -1, -1
	}
	serverConn, err := net.ListenUDP("udp4", etrServer)
	if err != nil {
		log.Printf("Unable to start ETR server on :4341: %s\n", err)
		return nil, nil, -1, -1
	}

	// Create a raw socket for injecting decapsulated packets
	fd1, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Creating ETR raw socket for packet injection failed: %s\n", err)
		serverConn.Close()
		return nil, nil, -1, -1
	}

	// start processing packets. This loop should never end.
	go ProcessETRPkts(fd1, serverConn)

	ring := SetupEtrPktCapture(ephPort)
	if ring == nil {
		log.Printf("Unable to create ETR packet capture.\n")
		return serverConn, nil, fd1, -1
	}

	fd2, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Printf("Creating second ETR raw socket for packet injection failed: %s\n", err)
		ring.Disable()
		ring.Close()
		return serverConn, nil, fd1, -1
	}
	go ProcessCapturedPkts(fd2, ring)

	return serverConn, ring, fd1, fd2
}

func verifyAndInject(fd6 int,
	buf []byte, n int,
	decapKeys *types.DecapKeys) bool {
	//var pktEid net.IP
	iid := fib.GetLispIID(buf[0:8])
	if iid == uint32(0xFFFFFF) {
		return true
	}
	log.Println("IID of packet is:", iid)
	packetOffset   := 8
	destAddrOffset := 24

	//useCrypto := false
	keyId := fib.GetLispKeyId(buf[0:8])
	if keyId != 0 {
		log.Printf("XXXXX Using KeyId %d\n", keyId)
		//useCrypto = true
		destAddrOffset += aes.BlockSize
		packetOffset   += aes.BlockSize

		if decapKeys == nil {
			return false
		}

		// compute and compare ICV of packet
		icvKey := decapKeys.Keys[keyId - 1].IcvKey
		if icvKey == nil {
			log.Printf("ETR Key id %d had nil ICV key value\n", keyId)
			return false
		}
		icv := fib.ComputeICV(buf[0: n - types.ICVLEN], icvKey)
		pktIcv := buf[n - types.ICVLEN: n]

		if !bytes.Equal(icv, pktIcv) {
			log.Printf("Pkt ICV %x and calculated ICV %x do not match.\n", pktIcv, icv)
			return false
		}
		log.Println("XXXXX ICVs match")

		// Decrypt the packet before sending out
		// read the IV from packet buffer
		ivArray := buf[8: packetOffset]

		packet := buf[packetOffset: n - types.ICVLEN]

		cryptoLen := n - packetOffset - types.ICVLEN
		if cryptoLen % 16 != 0 {
			log.Printf("XXXXX Crypto packet length is %d\n", cryptoLen)
			return false
		}

		if len(decapKeys.Keys) == 0 {
			log.Printf("ETR does not have decap keys from lispers.net yet\n")
			return false
		}

		// Always use key 1
		key := decapKeys.Keys[keyId - 1].DecKey

		// This should happen once. May be make it part of the database entry
		block, err := aes.NewCipher(key)
		if err != nil {
			log.Println("Error: creating key:", err)
			return false
		}
		mode := cipher.NewCBCDecrypter(block, ivArray)
		mode.CryptBlocks(packet, packet)
	}

	var destAddr [16]byte
	for i, _ := range destAddr {
		// offset is lisp hdr size + start offset of ip addresses in v6 hdr
		destAddr[i] = buf[8 + destAddrOffset + i]
		//pktEid[i] = destAddr[i]
	}

	err := syscall.Sendto(fd6, buf[packetOffset: n], 0, &syscall.SockaddrInet6{
		Port:   0,
		ZoneId: 0,
		Addr:   destAddr,
	})
	if err != nil {
		log.Printf("Failed injecting ETR packet: %s.\n", err)
		return false
	}
	return true
}

func SetupEtrPktCapture(ephemeralPort int) *pfring.Ring {
	var globalConfig types.DeviceNetworkConfig

	// Get the interface on which to listen for packets.
	// Current uplink interface information is stored in
	// /var/tmp/zedrouter/config/global
	cb, err := ioutil.ReadFile(uplinkFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, uplinkFileName)
		return nil
	}
	if err := json.Unmarshal(cb, &globalConfig); err != nil {
		log.Printf("%s DeviceNetworkConfig file: %s\n",
			err, uplinkFileName)
		return nil
	}

	// XXX hack hack
	// We open only the first interface in list for packet capture.
	// Later in future all interfaces in the list will have to be opened
	// for packet capture.
	/*
	for _, u := range globalConfig.Uplink {
		// open for packet capture
	}
	*/

	upLink := globalConfig.Uplink[0]

	ring, err := pfring.NewRing(upLink, 65536, pfring.FlagPromisc)
	if err != nil {
		log.Printf("ETR packet capture on interface %s failed: %s\n",
		upLink, err)
		return nil
	}

	// Set filter for UDP, source port = 4341, destination port = given ephemeral
	ring.SetDirection(pfring.ReceiveOnly)
	ring.SetSocketMode(pfring.ReadOnly)

	filter := fmt.Sprintf("udp dst port %d and udp src port 4341", ephemeralPort)
	ring.SetBPFFilter(filter)

	ring.SetPollWatermark(1)
	// set a poll duration of 1 hour
	ring.SetPollDuration(60 * 60 * 1000)

	err = ring.Enable()
	if err != nil {
		log.Printf("Enabling pfring on interface %s failed: %s\n", upLink, err)
		return nil
	}
	return ring
}

func ProcessETRPkts(fd6 int, serverConn *net.UDPConn) bool {
	// start processing packets. This loop should never end.
	buf := make([]byte, 65536)
	log.Printf("Started processing captured packets in ETR\n")

	for {
		n, saddr, err := serverConn.ReadFromUDP(buf)
		log.Println("XXXXX Received", n, "bytes in ETR")
		if err != nil {
			log.Printf("Fatal error during ETR processing\n")
			return false
		}
		decapKeys := fib.LookupDecapKeys(saddr.IP)
		ok := verifyAndInject(fd6, buf, n, decapKeys)
		if ok == false {
			log.Printf("Failed injecting ETR packet from port 4341\n")
		}
	}
}

func ProcessCapturedPkts(fd6 int, ring *pfring.Ring) {
	var pktBuf [65536]byte
	log.Printf("Started processing captured packets in ETR\n")

	for {
		ci, err := ring.ReadPacketDataTo(pktBuf[:])
		if err != nil {
			log.Printf("Error capturing packets: %s\n", err)
			log.Printf("It could be the ring closure leading to this.\n")
			return
		}
		capLen := ci.CaptureLength
		log.Printf("XXXXX Captured ETR packet of length %d\n", capLen)
		packet := gopacket.NewPacket(
			pktBuf[:capLen],
			layers.LinkTypeEthernet,
			gopacket.DecodeOptions{Lazy: false, NoCopy: true})

		appLayer := packet.ApplicationLayer()
		payload := appLayer.Payload()

		var srcIP net.IP
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			// ipv4 underlay
			ipHdr := ipLayer.(*layers.IPv4)
			srcIP = ipHdr.SrcIP
		} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
			// ipv6 underlay
			ip6Hdr := ipLayer.(*layers.IPv6)
			srcIP = ip6Hdr.SrcIP
		} else {
			// We do not need this packet
			return
		}

		decapKeys := fib.LookupDecapKeys(srcIP)

		//log.Println(payload)
		ok := verifyAndInject(fd6, payload, len(payload), decapKeys)
		if ok == false {
			log.Printf("Failed injecting ETR packet from ephemeral port\n")
		}
	}
}
