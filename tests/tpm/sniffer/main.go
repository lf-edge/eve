// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"unsafe"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var (
	realSocketPath   = flag.String("real", "/tmp/swtpm/srv.sock", "Path to the real swtpm socket")
	listenSocketPath = flag.String("listen", "/tmp/swtpm/srv.proxy.sock", "Path for the proxy socket to listen on")
)

// commandNames maps TPM2 command codes to human-readable names.
var commandNames = map[uint32]string{
	uint32(tpm2.CmdNVUndefineSpaceSpecial):     "NVUndefineSpaceSpecial",
	uint32(tpm2.CmdEvictControl):               "EvictControl",
	uint32(tpm2.CmdUndefineSpace):              "NVUndefineSpace",
	uint32(tpm2.CmdClear):                      "Clear",
	uint32(tpm2.CmdHierarchyChangeAuth):        "HierarchyChangeAuth",
	uint32(tpm2.CmdDefineSpace):                "NVDefineSpace",
	uint32(tpm2.CmdCreatePrimary):              "CreatePrimary",
	uint32(tpm2.CmdIncrementNVCounter):         "NVIncrement",
	uint32(tpm2.CmdWriteNV):                    "NVWrite",
	uint32(tpm2.CmdWriteLockNV):                "NVWriteLock",
	uint32(tpm2.CmdDictionaryAttackLockReset):  "DictionaryAttackLockReset",
	uint32(tpm2.CmdDictionaryAttackParameters): "DictionaryAttackParameters",
	uint32(tpm2.CmdPCREvent):                   "PCREvent",
	uint32(tpm2.CmdPCRReset):                   "PCRReset",
	uint32(tpm2.CmdSequenceComplete):           "SequenceComplete",
	uint32(tpm2.CmdStartup):                    "Startup",
	uint32(tpm2.CmdShutdown):                   "Shutdown",
	uint32(tpm2.CmdActivateCredential):         "ActivateCredential",
	uint32(tpm2.CmdCertify):                    "Certify",
	uint32(tpm2.CmdCertifyCreation):            "CertifyCreation",
	uint32(tpm2.CmdReadNV):                     "NVRead",
	uint32(tpm2.CmdReadLockNV):                 "NVReadLock",
	uint32(tpm2.CmdPolicySecret):               "PolicySecret",
	uint32(tpm2.CmdCreate):                     "Create",
	uint32(tpm2.CmdECDHZGen):                   "ECDHZGen",
	uint32(tpm2.CmdImport):                     "Import",
	uint32(tpm2.CmdLoad):                       "Load",
	uint32(tpm2.CmdQuote):                      "Quote",
	uint32(tpm2.CmdRSADecrypt):                 "RSADecrypt",
	uint32(tpm2.CmdSequenceUpdate):             "SequenceUpdate",
	uint32(tpm2.CmdSign):                       "Sign",
	uint32(tpm2.CmdUnseal):                     "Unseal",
	uint32(tpm2.CmdPolicySigned):               "PolicySigned",
	uint32(tpm2.CmdContextLoad):                "ContextLoad",
	uint32(tpm2.CmdContextSave):                "ContextSave",
	uint32(tpm2.CmdECDHKeyGen):                 "ECDHKeyGen",
	uint32(tpm2.CmdEncryptDecrypt):             "EncryptDecrypt",
	uint32(tpm2.CmdFlushContext):               "FlushContext",
	uint32(tpm2.CmdLoadExternal):               "LoadExternal",
	uint32(tpm2.CmdMakeCredential):             "MakeCredential",
	uint32(tpm2.CmdReadPublicNV):               "NVReadPublic",
	uint32(tpm2.CmdPolicyCommandCode):          "PolicyCommandCode",
	uint32(tpm2.CmdPolicyOr):                   "PolicyOr",
	uint32(tpm2.CmdReadPublic):                 "ReadPublic",
	uint32(tpm2.CmdRSAEncrypt):                 "RSAEncrypt",
	uint32(tpm2.CmdStartAuthSession):           "StartAuthSession",
	uint32(tpm2.CmdGetCapability):              "GetCapability",
	uint32(tpm2.CmdGetRandom):                  "GetRandom",
	uint32(tpm2.CmdHash):                       "Hash",
	uint32(tpm2.CmdPCRRead):                    "PCRRead",
	uint32(tpm2.CmdPolicyPCR):                  "PolicyPCR",
	uint32(tpm2.CmdReadClock):                  "ReadClock",
	uint32(tpm2.CmdPCRExtend):                  "PCRExtend",
	uint32(tpm2.CmdEventSequenceComplete):      "EventSequenceComplete",
	uint32(tpm2.CmdHashSequenceStart):          "HashSequenceStart",
	uint32(tpm2.CmdPolicyGetDigest):            "PolicyGetDigest",
	uint32(tpm2.CmdPolicyPassword):             "PolicyPassword",
	uint32(tpm2.CmdEncryptDecrypt2):            "EncryptDecrypt2",
	0x0000018A:                                 "TestParms",
}

type responseHeader struct {
	Tag  uint16
	Size uint32
	Res  uint32
}

type commandHeader struct {
	Tag  uint16
	Size uint32
	Cmd  uint32
}

func hexdump(data []byte, bytesPerLine int) {
	for i := 0; i < len(data); i += bytesPerLine {
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}
		fmt.Printf("%08x  ", i)
		for j := i; j < i+bytesPerLine; j++ {
			if j < len(data) {
				fmt.Printf("%02x ", data[j])
			} else {
				fmt.Print("   ")
			}
			if (j-i+1)%8 == 0 {
				fmt.Print(" ")
			}
		}
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

func cmdName(code uint32) string {
	if name, ok := commandNames[code]; ok {
		return name
	}
	return fmt.Sprintf("0x%08x", code)
}

func main() {
	flag.Parse()
	startProxy()
}

func startProxy() {
	if err := os.RemoveAll(*listenSocketPath); err != nil {
		fmt.Printf("Failed to clean up old proxy socket: %v\n", err)
		os.Exit(1)
	}

	proxyListener, err := net.Listen("unix", *listenSocketPath)
	if err != nil {
		fmt.Printf("Failed to create proxy socket: %v\n", err)
		os.Exit(1)
	}
	defer proxyListener.Close()
	fmt.Printf("Sniffer proxy listening on %s → %s\n", *listenSocketPath, *realSocketPath)

	for {
		clientConn, err := proxyListener.Accept()
		if err != nil {
			fmt.Printf("Error accepting client connection: %v\n", err)
			continue
		}
		go handleConnection(clientConn)
	}
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	realSwtpm, err := net.Dial("unix", *realSocketPath)
	if err != nil {
		fmt.Printf("Error connecting to swtpm: %v\n", err)
		return
	}
	defer realSwtpm.Close()
	proxy(realSwtpm, clientConn)
}

func proxy(realSwtpm, client net.Conn) {
	for {
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("Error reading data from client: %v\n", err)
			}
			return
		}

		data := buf[:n]

		ch := &commandHeader{}
		chSize := int(unsafe.Sizeof(*ch))
		if len(data) >= chSize {
			_, err = tpmutil.Unpack(data, ch)
			if err != nil {
				fmt.Printf("error unpacking command header: %v\n", err)
				return
			}
			fmt.Printf(">>> Command: %s (tag=0x%04x size=%d)\n", cmdName(ch.Cmd), ch.Tag, ch.Size)
		} else {
			fmt.Println(">>> Command (raw):")
		}
		hexdump(data, 16)

		_, err = realSwtpm.Write(data)
		if err != nil {
			fmt.Printf("Error writing data to swtpm: %v\n", err)
			return
		}

		n, err = realSwtpm.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Printf("error reading data from swtpm: %v\n", err)
			}
			return
		}

		data = buf[:n]

		rh := &responseHeader{}
		rhSize := int(unsafe.Sizeof(*rh))
		if len(data) >= rhSize {
			_, err = tpmutil.Unpack(data, rh)
			if err != nil {
				fmt.Printf("error unpacking response header: %v\n", err)
				return
			}
			fmt.Printf("<<< Response to %s: rc=0x%08x (tag=0x%04x size=%d)\n",
				cmdName(ch.Cmd), rh.Res, rh.Tag, rh.Size)
		} else {
			fmt.Println("<<< Response (raw):")
		}
		hexdump(data, 16)
		fmt.Println()

		_, err = client.Write(data)
		if err != nil {
			fmt.Printf("Error writing swtpm response to client: %v\n", err)
			return
		}
	}
}
