// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package evetpm

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// EK certificate NV indices, TCG EK Credential Profile 2.5, 2.2.1.4-2.2.1.5.
const (
	TpmEKCertRSAHdl  tpmutil.Handle = 0x01c00002
	TpmEKCertECCHdl  tpmutil.Handle = 0x01c0000a
	ekNVRangeFirst   tpmutil.Handle = 0x01c00000
	ekNVRangeLast    tpmutil.Handle = 0x01c07fff
	ekHighRangeFirst tpmutil.Handle = 0x01c00012
	ekChainFirst     tpmutil.Handle = 0x01c00100
	ekChainLast      tpmutil.Handle = 0x01c001ff
)

// quoteRetries bounds how often QuoteWithAIK re-reads the PCRs when one is
// extended between the read and the quote.
const quoteRetries = 3

// NVCertificate is an EK certificate read from TPM NV.
type NVCertificate struct {
	Index uint32 `json:"nv_index"`
	DER   []byte `json:"der"`
	// IssuerURLs is the certificate's Authority Information Access
	// caIssuers list, where a verifier fetches the issuing CA certificate.
	IssuerURLs []string `json:"issuer_urls,omitempty"`
}

// TpmIdentity describes the TPM part and the keys a verifier needs to check
// an AIK quote back to the TPM manufacturer.
type TpmIdentity struct {
	ManufacturerID  string `json:"manufacturer_id"`
	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
	// EKPublic and AIKPublic are TPMT_PUBLIC, AIKName is the TPM2B_NAME.
	EKPublic  []byte `json:"ek_public"`
	AIKPublic []byte `json:"aik_public"`
	AIKName   []byte `json:"aik_name"`
	// AIKHierarchy is the hierarchy the AIK lives in. Outside the
	// endorsement and platform hierarchies the TPM adds a per-key constant
	// to resetCount, restartCount and firmwareVersion in every attestation
	// (TPM 2.0 Part 3, 18.1); deltas between quotes stay exact.
	AIKHierarchy   string          `json:"aik_hierarchy"`
	EKCertificates []NVCertificate `json:"ek_certificates"`
	// EKCertChain holds the CA certificates the manufacturer stored in NV
	// (EK Credential Profile 2.5, 2.2.1.5.2), usually none.
	EKCertChain [][]byte `json:"ek_cert_chain,omitempty"`
}

// PCRDigest is one PCR value covered by a quote.
type PCRDigest struct {
	Index  int    `json:"index"`
	SHA256 []byte `json:"sha256"`
}

// AIKQuote is a TPM2_Quote by the AIK, with the PCR values it covers.
type AIKQuote struct {
	// Attest is the TPMS_ATTEST the AIK signed.
	Attest    []byte      `json:"attest"`
	Signature []byte      `json:"signature"`
	SigAlg    string      `json:"sig_alg"`
	PCRs      []PCRDigest `json:"pcrs"`
	// Decoded from Attest for convenience; Attest is authoritative.
	Clock           uint64 `json:"clock"`
	ResetCount      uint32 `json:"reset_count"`
	RestartCount    uint32 `json:"restart_count"`
	Safe            bool   `json:"safe"`
	FirmwareVersion uint64 `json:"firmware_version"`
}

// ReadTpmIdentity collects the TPM part description, the EK and AIK public
// areas, and the EK certificates. A TPM without EK certificates is not an
// error.
func ReadTpmIdentity(rw io.ReadWriter) (*TpmIdentity, error) {
	props := map[tpm2.TPMProp]uint32{}
	for _, p := range []tpm2.TPMProp{tpm2.Manufacturer, tpm2.VendorString1,
		tpm2.VendorString2, tpm2.VendorString3, tpm2.VendorString4,
		tpm2.FirmwareVersion1, tpm2.FirmwareVersion2} {
		v, err := getProperty(rw, p)
		if err != nil {
			return nil, err
		}
		props[p] = v
	}
	id := &TpmIdentity{
		ManufacturerID: propString(props[tpm2.Manufacturer]),
		Manufacturer:   vendorRegistry[props[tpm2.Manufacturer]],
		Model: propString(props[tpm2.VendorString1], props[tpm2.VendorString2],
			props[tpm2.VendorString3], props[tpm2.VendorString4]),
		FirmwareVersion: GetFirmwareVersion(props[tpm2.FirmwareVersion1],
			props[tpm2.FirmwareVersion2]),
		AIKHierarchy: "owner",
	}

	ekPub, _, _, err := tpm2.ReadPublic(rw, TpmEKHdl)
	if err != nil {
		return nil, fmt.Errorf("reading EK public: %w", err)
	}
	if id.EKPublic, err = ekPub.Encode(); err != nil {
		return nil, fmt.Errorf("encoding EK public: %w", err)
	}
	var aikName tpmutil.U16Bytes
	aikPub, aikName, _, err := tpm2.ReadPublic(rw, TpmAIKHdl)
	if err != nil {
		return nil, fmt.Errorf("reading AIK public: %w", err)
	}
	if id.AIKPublic, err = aikPub.Encode(); err != nil {
		return nil, fmt.Errorf("encoding AIK public: %w", err)
	}
	var name bytes.Buffer
	if err := aikName.TPMMarshal(&name); err != nil {
		return nil, fmt.Errorf("encoding AIK name: %w", err)
	}
	id.AIKName = name.Bytes()

	id.EKCertificates, id.EKCertChain, err = readEKCertificates(rw)
	if err != nil {
		return nil, err
	}
	return id, nil
}

// QuoteWithAIK quotes sel with the AIK over qualifyingData and returns the
// PCR values whose digest the quote attests. The PCRs are read separately, so
// a quote whose digest does not match them is retried.
func QuoteWithAIK(rw io.ReadWriter, qualifyingData []byte,
	sel tpm2.PCRSelection) (*AIKQuote, error) {
	for attempt := 0; attempt < quoteRetries; attempt++ {
		pcrs, err := readPCRSet(rw, sel)
		if err != nil {
			return nil, err
		}
		attest, sig, err := tpm2.Quote(rw, TpmAIKHdl, EmptyPassword,
			EmptyPassword, qualifyingData, sel, tpm2.AlgNull)
		if err != nil {
			return nil, fmt.Errorf("TPM2_Quote: %w", err)
		}
		ad, err := tpm2.DecodeAttestationData(attest)
		if err != nil {
			return nil, fmt.Errorf("decoding TPMS_ATTEST: %w", err)
		}
		if ad.AttestedQuoteInfo == nil {
			return nil, errors.New("TPMS_ATTEST carries no quote info")
		}
		values, digest := pcrDigest(pcrs, sel)
		if !bytes.Equal(digest, ad.AttestedQuoteInfo.PCRDigest) {
			continue
		}
		q := &AIKQuote{
			Attest:          attest,
			PCRs:            values,
			Clock:           ad.ClockInfo.Clock,
			ResetCount:      ad.ClockInfo.ResetCount,
			RestartCount:    ad.ClockInfo.RestartCount,
			Safe:            ad.ClockInfo.Safe == 1,
			FirmwareVersion: ad.FirmwareVersion,
		}
		switch sig.Alg {
		case tpm2.AlgRSASSA:
			q.SigAlg, q.Signature = "RSASSA-SHA256", sig.RSA.Signature
		case tpm2.AlgECDSA:
			q.SigAlg = "ECDSA-SHA256"
			q.Signature, err = asn1.Marshal(struct{ R, S *big.Int }{sig.ECC.R, sig.ECC.S})
			if err != nil {
				return nil, fmt.Errorf("encoding ECDSA signature: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported AIK signature algorithm %v", sig.Alg)
		}
		return q, nil
	}
	return nil, fmt.Errorf("PCRs changed during %d quote attempts", quoteRetries)
}

// readPCRSet reads every PCR in sel; one TPM2_PCR_Read returns at most 8.
func readPCRSet(rw io.ReadWriter, sel tpm2.PCRSelection) (map[int][]byte, error) {
	pcrs := make(map[int][]byte, len(sel.PCRs))
	for start := 0; start < len(sel.PCRs); start += 8 {
		end := min(start+8, len(sel.PCRs))
		part, err := tpm2.ReadPCRs(rw, tpm2.PCRSelection{Hash: sel.Hash,
			PCRs: sel.PCRs[start:end]})
		if err != nil {
			return nil, fmt.Errorf("reading PCRs: %w", err)
		}
		for i, v := range part {
			pcrs[i] = v
		}
	}
	for _, i := range sel.PCRs {
		if _, ok := pcrs[i]; !ok {
			return nil, fmt.Errorf("TPM did not return PCR %d", i)
		}
	}
	return pcrs, nil
}

func pcrDigest(pcrs map[int][]byte, sel tpm2.PCRSelection) ([]PCRDigest, []byte) {
	idx := append([]int(nil), sel.PCRs...)
	sort.Ints(idx)
	h := sha256.New()
	values := make([]PCRDigest, 0, len(idx))
	for _, i := range idx {
		h.Write(pcrs[i])
		values = append(values, PCRDigest{Index: i, SHA256: pcrs[i]})
	}
	return values, h.Sum(nil)
}

func getProperty(rw io.ReadWriter, p tpm2.TPMProp) (uint32, error) {
	vals, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, uint32(p))
	if err != nil {
		return 0, fmt.Errorf("reading TPM property %#x: %w", uint32(p), err)
	}
	if len(vals) == 0 {
		return 0, fmt.Errorf("TPM property %#x missing", uint32(p))
	}
	prop, ok := vals[0].(tpm2.TaggedProperty)
	if !ok || prop.Tag != p {
		return 0, fmt.Errorf("TPM property %#x missing", uint32(p))
	}
	return prop.Value, nil
}

// propString decodes TPM property words that hold big-endian ASCII.
func propString(words ...uint32) string {
	var b []byte
	for _, w := range words {
		b = append(b, byte(w>>24), byte(w>>16), byte(w>>8), byte(w))
	}
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return -1
		}
		return r
	}, string(b)))
}

func definedNVIndices(rw io.ReadWriter, first, last tpmutil.Handle) ([]tpmutil.Handle, error) {
	var out []tpmutil.Handle
	next := uint32(first)
	for {
		vals, more, err := tpm2.GetCapability(rw, tpm2.CapabilityHandles, 64, next)
		if err != nil {
			return nil, fmt.Errorf("listing NV indices: %w", err)
		}
		for _, v := range vals {
			h, ok := v.(tpmutil.Handle)
			if !ok || h > last {
				return out, nil
			}
			out = append(out, h)
			next = uint32(h) + 1
		}
		if !more || len(vals) == 0 {
			return out, nil
		}
	}
}

func readNV(rw io.ReadWriter, idx tpmutil.Handle) ([]byte, error) {
	pub, err := tpm2.NVReadPublic(rw, idx)
	if err != nil {
		return nil, err
	}
	auth := tpm2.HandleOwner
	if pub.Attributes&tpm2.AttrAuthRead != 0 {
		auth = idx
	}
	return tpm2.NVReadEx(rw, idx, auth, EmptyPassword, 0)
}

func readEKCertificates(rw io.ReadWriter) ([]NVCertificate, [][]byte, error) {
	indices, err := definedNVIndices(rw, ekNVRangeFirst, ekNVRangeLast)
	if err != nil {
		return nil, nil, err
	}
	var certs []NVCertificate
	var chainBlob []byte
	for _, idx := range indices {
		isLow := idx == TpmEKCertRSAHdl || idx == TpmEKCertECCHdl
		isChain := idx >= ekChainFirst && idx <= ekChainLast
		isHigh := idx >= ekHighRangeFirst && !isChain
		if !isLow && !isChain && !isHigh {
			continue
		}
		data, err := readNV(rw, idx)
		if err != nil {
			return nil, nil, fmt.Errorf("reading NV %#x: %w", uint32(idx), err)
		}
		if isChain {
			chainBlob = append(chainBlob, data...)
			continue
		}
		// High-range indices also hold EK templates; keep certificates only.
		// Some vendors pad the DER, so parse only the leading SEQUENCE.
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(data, &raw); err != nil {
			continue
		}
		cert, err := x509.ParseCertificate(raw.FullBytes)
		if err != nil {
			continue
		}
		certs = append(certs, NVCertificate{Index: uint32(idx),
			DER: raw.FullBytes, IssuerURLs: cert.IssuingCertificateURL})
	}
	var chain [][]byte
	if len(chainBlob) > 0 {
		parsed, err := x509.ParseCertificates(chainBlob)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing EK certificate chain from NV: %w", err)
		}
		for _, c := range parsed {
			chain = append(chain, c.Raw)
		}
	}
	return certs, chain, nil
}
