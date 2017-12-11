package etr

import (
	"fmt"
	"net"
	"os"
	"syscall"
	//"github.com/google/gopacket"
	//"github.com/google/gopacket/layers"
	"github.com/zededa/go-provision/dataplane/fib"
)

func StartETR() bool {
	// create a udp server socket and start listening on port 4341
	server, err := net.ResolveUDPAddr("udp", ":4341")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving ETR socket address\n")
		return false
	}
	serverConn, err := net.ListenUDP("udp", server)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to start ETR server on :4341: %s\n", err)
		return false
	}
	defer serverConn.Close()

	// Create a raw socket for injecting decapsulated packets
	fd6, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	//conn, err := net.ListenPacket("ip6:udp", "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Creating ETR raw socket for packet injection failed.\n")
		return false
	}
	defer syscall.Close(fd6)

	buf := make([]byte, 65536)

	// start processing packets. This loop should never end.
	for {
		n, _, err := serverConn.ReadFromUDP(buf)
		fmt.Println("Received", n, "bytes in ETR")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Fatal error during ETR processing\n")
			return false
		}
		verifyAndInject(fd6, buf, n)
	}

	return true
}

func verifyAndInject(fd6 int, buf []byte, n int) {
	//var pktEid net.IP
	iid := fib.GetLispIID(buf[0:8])
	fmt.Println("IID of packet is:", iid)
	fmt.Println("Inner packet is:")
	for _, b := range buf[8:n] {
		fmt.Printf("0x%x ", b)
	}
	fmt.Println()
	var destAddr [16]byte
	for i, _ := range destAddr {
		destAddr[i] = buf[8+24+i]
		//pktEid[i] = destAddr[i]
	}
	/*
		packet := gopacket.NewPacket(buf[8: n],
									layers.LinkTypeIPv6,
									gopacket.Default)
		if packet == nil {
			fmt.Fprintf(os.Stderr, "Packet decode failure\n");
			return
		}

		ip6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ip6Layer == nil {
			fmt.Fprintf(os.Stderr, "Extracting ipv6 header failed\n")
			return
		}

		ipHeader := ip6Layer.(*layers.IPv6)
		dstAddr := ipHeader.DstIP
	*/

	/*
		eids := fib.LookupIfaceEids(iid)
		matchFound := false

		for _, eid := range eids {
			if pktEid.Equal(eid) == true {
				matchFound = true
			}
		}
		if matchFound == false {
			fmt.Fprintf(os.Stderr,
			"Incoming packet is not destined to any of the EIDs belonging to us.\n")
			fmt.Fprintf(os.Stderr,
			"Incoming packet is destined to %s.\n", destAddr)
			return
		}
	*/

	/*
		v6Addr := ipHeader.DstIP.To16()
		var destAddr [16]byte
		for i, _ := range destAddr {
			destAddr[i] = v6Addr[i]
		}
	*/

	//_, err := conn.WriteTo(buf[8: n], &net.IPAddr{IP: ipHeader.DstIP})
	err := syscall.Sendto(fd6, buf[8:n], 0, &syscall.SockaddrInet6{
		Port:   0,
		ZoneId: 0,
		Addr:   destAddr,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed injecting ETR packet: %s.\n", err)
	}
}
