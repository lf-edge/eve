// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2/mu"
)

// TPMManufacturer corresponds to the TPM manufacturer and is returned
// when querying the value [PropertyManufacturer].
type TPMManufacturer uint32

const (
	TPMManufacturerAMD  TPMManufacturer = 0x414D4400 // AMD
	TPMManufacturerATML TPMManufacturer = 0x41544D4C // Atmel
	TPMManufacturerBRCM TPMManufacturer = 0x4252434D // Broadcom
	TPMManufacturerHPE  TPMManufacturer = 0x48504500 // HPE
	TPMManufacturerIBM  TPMManufacturer = 0x49424d00 // IBM
	TPMManufacturerIFX  TPMManufacturer = 0x49465800 // Infineon
	TPMManufacturerINTC TPMManufacturer = 0x494E5443 // Intel
	TPMManufacturerLEN  TPMManufacturer = 0x4C454E00 // Lenovo
	TPMManufacturerMSFT TPMManufacturer = 0x4D534654 // Microsoft
	TPMManufacturerNSM  TPMManufacturer = 0x4E534D20 // National Semiconductor
	TPMManufacturerNTZ  TPMManufacturer = 0x4E545A00 // Nationz
	TPMManufacturerNTC  TPMManufacturer = 0x4E544300 // Nuvoton Technology
	TPMManufacturerQCOM TPMManufacturer = 0x51434F4D // Qualcomm
	TPMManufacturerSMSC TPMManufacturer = 0x534D5343 // SMSC
	TPMManufacturerSTM  TPMManufacturer = 0x53544D20 // ST Microelectronics
	TPMManufacturerSMSN TPMManufacturer = 0x534D534E // Samsung
	TPMManufacturerSNS  TPMManufacturer = 0x534E5300 // Sinosun
	TPMManufacturerTXN  TPMManufacturer = 0x54584E00 // Texas Instruments
	TPMManufacturerWEC  TPMManufacturer = 0x57454300 // Winbond
	TPMManufacturerROCC TPMManufacturer = 0x524F4343 // Fuzhou Rockchip
	TPMManufacturerGOOG TPMManufacturer = 0x474F4F47 // Google
)

// PCRValues contains a collection of PCR values, keyed by HashAlgorithmId and
// PCR index. It can be marshalled to and from the TPM wire format.
type PCRValues map[HashAlgorithmId]map[int]Digest

// Marshal implements [mu.CustomMarshaller.Marshal].
func (v PCRValues) Marshal(w io.Writer) error {
	pcrs, digests, err := v.ToListAndSelection()
	if err != nil {
		return err
	}
	_, err = mu.MarshalToWriter(w, pcrs, digests)
	return err
}

// Unmarshal implements [mu.CustomMarshaller.Unmarshal].
func (v *PCRValues) Unmarshal(r io.Reader) error {
	v2 := make(PCRValues)
	*v = v2

	var pcrs PCRSelectionList
	var digests DigestList
	if _, err := mu.UnmarshalFromReader(r, &pcrs, &digests); err != nil {
		return err
	}

	n, err := v2.AddValues(pcrs, digests)
	if err != nil {
		return err
	}
	if n != len(digests) {
		return errors.New("too many digests")
	}

	return nil
}

// SelectionList computes a list of PCR selections corresponding to this set of PCR
// values. This will always return a valid selection or an error.
func (v PCRValues) SelectionList() (PCRSelectionList, error) {
	var out PCRSelectionList
	for h := range v {
		s := PCRSelection{Hash: h}
		for p := range v[h] {
			s.Select = append(s.Select, p)
		}
		out = append(out, s)
	}
	return out.Sort()
}

// ToListAndSelection converts this set of PCR values to a list of PCR
// selections and list of PCR values in a form that can be serialized,
// although if you want to do that then you can pass PCRValues directly
// to [mu.MarshalToBytes] or [mu.MarshalToWriter].
func (v PCRValues) ToListAndSelection() (pcrs PCRSelectionList, digests DigestList, err error) {
	pcrs, err = v.SelectionList()
	if err != nil {
		return nil, nil, err
	}
	for _, p := range pcrs {
		if !p.Hash.IsValid() {
			return nil, nil, errors.New("invalid digest algorithm")
		}
		for _, s := range p.Select {
			digest := v[p.Hash][s]
			if len(digest) != p.Hash.Size() {
				return nil, nil, errors.New("invalid digest size")
			}
			digests = append(digests, digest)
		}
	}
	return pcrs, digests, nil
}

// AddValues the PCR values from the supplied list of PCR selections and list
// of values.
func (v PCRValues) AddValues(pcrs PCRSelectionList, digests DigestList) (n int, err error) {
	for _, p := range pcrs {
		if !p.Hash.IsValid() {
			return 0, errors.New("invalid digest algorithm")
		}

		// Convert the selection to a bitmap and then back again
		// to ensure it is ordered correctly.
		bmp, err := p.Select.ToBitmap(0)
		if err != nil {
			return 0, fmt.Errorf("invalid selection: %w", err)
		}
		sel := bmp.ToPCRs()

		if _, ok := v[p.Hash]; !ok {
			v[p.Hash] = make(map[int]Digest)
		}

		for _, s := range sel {
			if len(digests) == 0 {
				return 0, errors.New("insufficient digests")
			}
			d := digests[0]
			digests = digests[1:]
			if len(d) != p.Hash.Size() {
				return 0, errors.New("invalid digest size")
			}
			v[p.Hash][s] = d
			n++
		}
	}
	return n, nil
}

// SetValue sets the PCR value for the specified PCR and PCR bank.
func (v PCRValues) SetValue(alg HashAlgorithmId, pcr int, digest Digest) error {
	if !alg.IsValid() {
		return errors.New("invalid algorithm")
	}
	sel := PCRSelect{pcr}
	if _, err := sel.ToBitmap(0); err != nil {
		return errors.New("invalid PCR")
	}
	if len(digest) != alg.Size() {
		return errors.New("invalid digest size")
	}
	if _, ok := v[alg]; !ok {
		v[alg] = make(map[int]Digest)
	}
	v[alg][pcr] = digest
	return nil
}

// PublicTemplate exists to allow a type to be marshalled to the
// Template type.
type PublicTemplate interface {
	ToTemplate() (Template, error)
}
