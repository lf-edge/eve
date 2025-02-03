// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// Section 30 - Capability Commands

// GetCapabilityRaw executes the TPM2_GetCapability command, which returns various properties of
// the TPM and its current state. The capability parameter indicates the category of data to be
// returned. The property parameter indicates the first value of the selected category to be
// returned. The propertyCount parameter indicates the number of values to be returned.
//
// If no property in the TPM corresponds to the value of property, then the next property is
// returned.
//
// The underlying implementation of TPM2_GetCapability is not required to (or may not be able to)
// return all of the requested values in a single request.
//
// If capability is [CapabilityHandles] and property does not correspond to a valid handle type, a
// *[TPMParameterError] error with an error code of [ErrorHandle] is returned for parameter index
// 2.
//
// On success, a capability structure is returned containing the requested number of properties,
// the number of properties available, or the number of properties that could be returned,
// whichever is less. If there are more properties in the selected category, moreData will be true
// whether the remaining properties were requested or not.
func (t *TPMContext) GetCapabilityRaw(capability Capability, property, propertyCount uint32, sessions ...SessionContext) (moreData bool, capabilityData *CapabilityData, err error) {
	if err := t.StartCommand(CommandGetCapability).
		AddParams(capability, property, propertyCount).
		AddExtraSessions(sessions...).
		Run(nil, &moreData, &capabilityData); err != nil {
		return false, nil, err
	}
	return moreData, capabilityData, nil
}

// GetCapability executes the TPM2_GetCapability command, which returns various properties of the
// TPM and its current state. The capability parameter indicates the category of data to be
// returned. The property parameter indicates the first value of the selected category to be
// returned. The propertyCount parameter indicates the number of values to be returned.
//
// If no property in the TPM corresponds to the value of property, then the next property is
// returned.
//
// The underlying implementation of TPM2_GetCapability is not required to (or may not be able to)
// return all of the requested values in a single request. This function will re-execute the
// TPM2_GetCapability command until all of the requested properties have been returned. As a
// consequence, any [SessionContext] instances provided should have the [AttrContinueSession]
// attribute defined.
//
// If capability is [CapabilityHandles] and property does not correspond to a valid handle type, a
// *[TPMParameterError] error with an error code of [ErrorHandle] is returned for parameter index
// 2.
//
// On success, a capability structure is returned containing the requested number of properties,
// or the number of properties available, whichever is less.
func (t *TPMContext) GetCapability(capability Capability, property, propertyCount uint32, sessions ...SessionContext) (capabilityData *CapabilityData, err error) {
	capabilityData = &CapabilityData{Capability: capability, Data: &CapabilitiesU{}}

	nextProperty := property
	remaining := propertyCount

	for {
		moreData, data, err := t.GetCapabilityRaw(capability, nextProperty, remaining, sessions...)
		if err != nil {
			return nil, err
		}

		if data.Capability != capability {
			return nil, &InvalidResponseError{CommandGetCapability,
				fmt.Errorf("TPM responded with data for the wrong capability (got %s)", data.Capability)}
		}

		var l int
		var p uint32
		switch data.Capability {
		case CapabilityAlgs:
			capabilityData.Data.Algorithms = append(capabilityData.Data.Algorithms, data.Data.Algorithms...)
			l = len(data.Data.Algorithms)
			if l > 0 {
				p = uint32(data.Data.Algorithms[l-1].Alg)
			}
		case CapabilityHandles:
			capabilityData.Data.Handles = append(capabilityData.Data.Handles, data.Data.Handles...)
			l = len(data.Data.Handles)
			if l > 0 {
				p = uint32(data.Data.Handles[l-1])
			}
		case CapabilityCommands:
			capabilityData.Data.Command = append(capabilityData.Data.Command, data.Data.Command...)
			l = len(data.Data.Command)
			if l > 0 {
				p = uint32(data.Data.Command[l-1].CommandCode())
			}
		case CapabilityPPCommands:
			capabilityData.Data.PPCommands = append(capabilityData.Data.PPCommands, data.Data.PPCommands...)
			l = len(data.Data.PPCommands)
			if l > 0 {
				p = uint32(data.Data.PPCommands[l-1])
			}
		case CapabilityAuditCommands:
			capabilityData.Data.AuditCommands = append(capabilityData.Data.AuditCommands, data.Data.AuditCommands...)
			l = len(data.Data.AuditCommands)
			if l > 0 {
				p = uint32(data.Data.AuditCommands[l-1])
			}
		case CapabilityPCRs:
			if moreData {
				return nil, &InvalidResponseError{CommandGetCapability,
					fmt.Errorf("TPM did not respond with all requested properties for capability %s", data.Capability)}
			}
			return data, nil
		case CapabilityTPMProperties:
			capabilityData.Data.TPMProperties = append(capabilityData.Data.TPMProperties, data.Data.TPMProperties...)
			l = len(data.Data.TPMProperties)
			if l > 0 {
				p = uint32(data.Data.TPMProperties[l-1].Property)
			}
		case CapabilityPCRProperties:
			capabilityData.Data.PCRProperties = append(capabilityData.Data.PCRProperties, data.Data.PCRProperties...)
			l = len(data.Data.PCRProperties)
			if l > 0 {
				p = uint32(data.Data.PCRProperties[l-1].Tag)
			}
		case CapabilityECCCurves:
			capabilityData.Data.ECCCurves = append(capabilityData.Data.ECCCurves, data.Data.ECCCurves...)
			l = len(data.Data.ECCCurves)
			if l > 0 {
				p = uint32(data.Data.ECCCurves[l-1])
			}
		case CapabilityAuthPolicies:
			capabilityData.Data.AuthPolicies = append(capabilityData.Data.AuthPolicies, data.Data.AuthPolicies...)
			l = len(data.Data.AuthPolicies)
			if l > 0 {
				p = uint32(data.Data.AuthPolicies[l-1].Handle)
			}
		}

		nextProperty += p + 1
		remaining -= uint32(l)

		if !moreData || remaining <= 0 {
			break
		}
	}

	return capabilityData, nil
}

// GetCapabilityAlgs is a convenience function for [TPMContext.GetCapability], and returns
// properties of the algorithms supported by the TPM. The first parameter indicates the first
// algorithm for which to return properties. If this algorithm isn't supported, then the
// properties of the next supported algorithm are returned instead. The propertyCount parameter
// indicates the number of algorithms for which to return properties.
func (t *TPMContext) GetCapabilityAlgs(first AlgorithmId, propertyCount uint32, sessions ...SessionContext) (algs AlgorithmPropertyList, err error) {
	data, err := t.GetCapability(CapabilityAlgs, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Algorithms, nil
}

// GetCapabilityAlg is a convenience function for [TPMContext.GetCapability] that returns the
// properties of the specified algorithm if it is supported by the TPM. If it isn't supported, an
// error is returned.
func (t *TPMContext) GetCapabilityAlg(alg AlgorithmId, sessions ...SessionContext) (AlgorithmProperty, error) {
	algs, err := t.GetCapabilityAlgs(alg, 1, sessions...)
	if err != nil {
		return AlgorithmProperty{}, err
	}
	if len(algs) == 0 || algs[0].Alg != alg {
		return AlgorithmProperty{}, fmt.Errorf("algorithm %v does not exist", alg)
	}
	return algs[0], nil
}

// IsAlgorithmSupported is a convenience function for [TPMContext.GetCapability] that determines if
// the specified algorithm is supported by the TPM. Note that this will indicate that the algorithm
// is unsupported if the TPM returns an error.
func (t *TPMContext) IsAlgorithmSupported(alg AlgorithmId, sessions ...SessionContext) bool {
	if _, err := t.GetCapabilityAlg(alg, sessions...); err != nil {
		return false
	}
	return true
}

// GetCapabilityCommands is a convenience function for [TPMContext.GetCapability], and returns
// attributes of the commands supported by the TPM. The first parameter indicates the first command
// for which to return attributes. If this command isn't supported, then the attributes of the next
// supported command are returned instead. The propertyCount parameter indicates the number of
// commands for which to return attributes.
func (t *TPMContext) GetCapabilityCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (commands CommandAttributesList, err error) {
	data, err := t.GetCapability(CapabilityCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Command, nil
}

// GetCapabilityCommand is a convenience function for [TPMContext.GetCapability] that returns the
// attributes of the specified command if it is supported by the TPM. If it isn't supported, an
// error is returned.
func (t *TPMContext) GetCapabilityCommand(code CommandCode, sessions ...SessionContext) (CommandAttributes, error) {
	commands, err := t.GetCapabilityCommands(code, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(commands) == 0 || commands[0].CommandCode() != code {
		return 0, fmt.Errorf("command %v does not exist", code)
	}
	return commands[0], nil
}

// IsCommandSupported is a convenience function for [TPMContext.GetCapability] that determines if
// the specified command is supported by the TPM. Note that this will indicate that the command is
// unsupported if the TPM returns an error.
func (t *TPMContext) IsCommandSupported(code CommandCode, sessions ...SessionContext) bool {
	if _, err := t.GetCapabilityCommand(code, sessions...); err != nil {
		return false
	}
	return true
}

// GetCapabilityPPCommands is a convenience function for [TPMContext.GetCapability], and returns a
// list of commands that require physical presence for platform authorization. The first parameter
// indicates the command code at which the returned list should start. The propertyCount parameter
// indicates the maximum number of command codes to return.
func (t *TPMContext) GetCapabilityPPCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (ppCommands CommandCodeList, err error) {
	data, err := t.GetCapability(CapabilityPPCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PPCommands, nil
}

// GetCapabilityAuditCommands is a convenience function for [TPMContext.GetCapability], and returns
// a list of commands that are currently set for command audit. The first parameter indicates the
// command code at which the returned list should start. The propertyCount parameter indicates the
// maximum number of command codes to return.
func (t *TPMContext) GetCapabilityAuditCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (auditCommands CommandCodeList, err error) {
	data, err := t.GetCapability(CapabilityAuditCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuditCommands, nil
}

// GetCapabilityHandles is a convenience function for [TPMContext.GetCapability], and returns a
// list of handles of resources on the TPM. The firstHandle parameter indicates the type of handles
// to be returned (represented by the most-significant byte), and also the handle at which the list
// should start. The propertyCount parameter indicates the maximum number of handles to return.
func (t *TPMContext) GetCapabilityHandles(firstHandle Handle, propertyCount uint32, sessions ...SessionContext) (handles HandleList, err error) {
	data, err := t.GetCapability(CapabilityHandles, uint32(firstHandle), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Handles, nil
}

// DoesHandleExist is a convenience function for [TPMContext.GetCapability] that determines if a
// resource with the specified handle exists on the TPM. This will indicate that the resource does
// not exist if the TPM returns an error. If handle corresponds to a session, this will only return
// true if the session is loaded.
func (t *TPMContext) DoesHandleExist(handle Handle, sessions ...SessionContext) bool {
	origHandle := handle
	if handle.Type() == HandleTypeSavedSession {
		handle &= 0x00ffffff
		handle |= Handle(HandleTypeLoadedSession) << 24
	}

	handles, err := t.GetCapabilityHandles(handle, 1, sessions...)
	if err != nil {
		return false
	}
	if len(handles) == 0 || handles[0] != origHandle {
		return false
	}
	return true
}

// DoesSavedSessionExist is a convenience function for [TPMContext.GetCapability] that determines
// if the specified handle corresponds to a saved session. This will indicate that there is no
// saved session if the TPM returns an error.
func (t *TPMContext) DoesSavedSessionExist(handle Handle, sessions ...SessionContext) bool {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		// ok
	default:
		return false
	}

	handle &= 0x00ffffff
	handle |= Handle(HandleTypeSavedSession) << 24

	handles, err := t.GetCapabilityHandles(handle, 1, sessions...)
	if err != nil {
		return false
	}

	handle &= 0x00ffffff
	handle |= Handle(HandleTypeHMACSession) << 24
	if len(handles) == 0 || handles[0] != handle {
		return false
	}
	return true
}

// GetCapabilityPCRs is a convenience function for [TPMContext.GetCapability], and returns the
// current allocation of PCRs on the TPM.
func (t *TPMContext) GetCapabilityPCRs(sessions ...SessionContext) (pcrs PCRSelectionList, err error) {
	data, err := t.GetCapability(CapabilityPCRs, 0, CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AssignedPCR, nil
}

// GetCapabilityTPMProperties is a convenience function for [TPMContext.GetCapability], and returns
// the values of properties of the TPM. The first parameter indicates the first property for which
// to return a value. If the property does not exist, then the value of the next available property
// is returned. The propertyCount parameter indicates the number of properties for which to return
// values.
func (t *TPMContext) GetCapabilityTPMProperties(first Property, propertyCount uint32, sessions ...SessionContext) (tpmProperties TaggedTPMPropertyList, err error) {
	data, err := t.GetCapability(CapabilityTPMProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.TPMProperties, nil
}

// GetCapabilityTPMProperty is a convenience function for [TPMContext.GetCapability] that returns
// the value of the specified property if it exists. If it doesn't exist, an error is returned.
func (t *TPMContext) GetCapabilityTPMProperty(property Property, sessions ...SessionContext) (uint32, error) {
	props, err := t.GetCapabilityTPMProperties(property, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(props) == 0 || props[0].Property != property {
		return 0, fmt.Errorf("property %v does not exist", property)
	}
	return props[0].Value, nil
}

// GetManufacturer is a convenience function for [TPMContext.GetCapability] that returns the ID of
// the TPM manufacturer.
func (t *TPMContext) GetManufacturer(sessions ...SessionContext) (manufacturer TPMManufacturer, err error) {
	m, err := t.GetCapabilityTPMProperty(PropertyManufacturer, sessions...)
	if err != nil {
		return 0, err
	}
	return TPMManufacturer(m), nil
}

// GetInputBuffer is a convenience function for [TPMContext.GetCapability] that returns the value
// of the [PropertyInputBuffer] property, which indicates the maximum size of arguments of the
// [MaxBuffer] type in bytes. The size is TPM implementation specific, but required to be at least
// 1024 bytes.
func (t *TPMContext) GetInputBuffer(sessions ...SessionContext) int {
	n, err := t.GetCapabilityTPMProperty(PropertyInputBuffer, sessions...)
	if err != nil {
		return 1024
	}
	return int(n)
}

// GetMaxDigest is a convenience function for [TPMContext.GetCapability] that returns the value of
// the [PropertyMaxDigest] property, which indicates the size of the largest digest algorithm
// supported by the TPM in bytes.
func (t *TPMContext) GetMaxDigest(sessions ...SessionContext) (int, error) {
	n, err := t.GetCapabilityTPMProperty(PropertyMaxDigest, sessions...)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// GetMaxData is a convenience function for [TPMContext.GetCapability] that returns the maximum
// size of arguments of the [Data] type supported by the TPM in bytes.
func (t *TPMContext) GetMaxData(sessions ...SessionContext) (int, error) {
	n, err := t.GetMaxDigest(sessions...)
	if err != nil {
		return 0, err
	}
	return n + binary.Size(AlgorithmId(0)), nil
}

// GetNVBufferMax is a convenience function for [TPMContext.GetCapability] that returns the value
// of the [PropertyNVBufferMax] property, which indicates the maximum buffer size supported by the
// TPM in bytes for [TPMContext.NVReadRaw] and [TPMContext.NVWriteRaw].
func (t *TPMContext) GetNVBufferMax(sessions ...SessionContext) (int, error) {
	n, err := t.GetCapabilityTPMProperty(PropertyNVBufferMax, sessions...)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// GetNVIndexMax is a convenience function for [TPMContext.GetCapability] that returns the value of
// the [PropertyNVIndexMax] property, which indicates the maximum size of a single NV index.
func (t *TPMContext) GetNVIndexMax(sessions ...SessionContext) (int, error) {
	n, err := t.GetCapabilityTPMProperty(PropertyNVIndexMax, sessions...)
	if err != nil {
		return 0, err
	}
	return int(n), nil
}

// GetMinPCRSelectSize is a convenience function for [TPMContext.GetCapability] that returns the
// value of the [PropertyPCRSelectMin] property, which indicates the minimum number of bytes in a
// PCR selection.
func (t *TPMContext) GetMinPCRSelectSize(sessions ...SessionContext) (uint8, error) {
	n, err := t.GetCapabilityTPMProperty(PropertyPCRSelectMin, sessions...)
	if err != nil {
		return 0, err
	}
	if n > math.MaxUint8 {
		return 0, errors.New("value out of range")
	}
	return uint8(n), nil
}

// GetCapabilityPCRProperties is a convenience function for [TPMContext.GetCapability], and returns
// the values of PCR properties. The first parameter indicates the first property for which to
// return a value. If the property does not exist, then the value of the next available property is
// returned. The propertyCount parameter indicates the number of properties for which to return
// values. Each returned property value is a list of PCR indexes associated with a property.
func (t *TPMContext) GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32, sessions ...SessionContext) (pcrProperties TaggedPCRPropertyList, err error) {
	data, err := t.GetCapability(CapabilityPCRProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PCRProperties, nil
}

// GetCapabilityECCCurves is a convenience function for [TPMContext.GetCapability], and returns a
// list of ECC curves supported by the TPM.
func (t *TPMContext) GetCapabilityECCCurves(sessions ...SessionContext) (eccCurves ECCCurveList, err error) {
	data, err := t.GetCapability(CapabilityECCCurves, uint32(ECCCurveFirst), CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.ECCCurves, nil
}

// IsECCCurveSupported is a convenience function for [TPMContext.GetCapability] that determines if
// the specified curve is supported. This will indicate that the specified curve is unsupported if
// the TPM returns an error.
func (t *TPMContext) IsECCCurveSupported(curve ECCCurve, sessions ...SessionContext) bool {
	curves, err := t.GetCapabilityECCCurves(sessions...)
	if err != nil {
		return false
	}
	for _, supported := range curves {
		if supported == curve {
			return true
		}
	}
	return false
}

// GetCapabilityAuthPolicies is a convenience function for [TPMContext.GetCapability], and returns
// auth policy digests associated with permanent handles. The first parameter indicates the first
// handle for which to return an auth policy. If the handle doesn't exist, then the auth policy
// for the next available handle is returned. The propertyCount parameter indicates the number of
// permanent handles for which to return an auth policy.
func (t *TPMContext) GetCapabilityAuthPolicies(first Handle, propertyCount uint32, sessions ...SessionContext) (authPolicies TaggedPolicyList, err error) {
	data, err := t.GetCapability(CapabilityAuthPolicies, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuthPolicies, nil
}

// IsTPM2 determines whether this TPMContext is connected to a TPM2 device. It does this by
// attempting to execute a TPM2_GetCapability command, and verifying that the response packet has
// the expected tag.
//
// On success, this will return true if TPMContext is connected to a TPM2 device, or false if it is
// connected to a TPM1.2 device. It will return false if communication with the device fails of if
// the response is badly formed.
func (t *TPMContext) IsTPM2() (isTpm2 bool) {
	_, err := t.GetCapabilityTPMProperties(PropertyTotalCommands, 0)
	if _, ok := err.(*TPMErrorBadTag); ok {
		return false
	}
	return true
}

// TestParms executes the TPM2_TestParms command to check if the specified combination of algorithm
// parameters is supported.
func (t *TPMContext) TestParms(parameters *PublicParams, sessions ...SessionContext) error {
	return t.StartCommand(CommandTestParms).AddParams(parameters).AddExtraSessions(sessions...).Run(nil)
}

// IsRSAKeySizeSupporters is a convenience function around [TPMContext.TestParms] that determines
// whether the specified RSA key size is supported.
func (t *TPMContext) IsRSAKeySizeSupported(keyBits uint16, sessions ...SessionContext) bool {
	params := PublicParams{
		Type: ObjectTypeRSA,
		Parameters: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   keyBits,
				Exponent:  0}}}
	if err := t.TestParms(&params, sessions...); err != nil {
		return false
	}
	return true
}

// IsSymmetricAlgorithmSupported is a convenience function around [TPMContext.TestParms] that
// determines whether the specified symmetric algorithm and key size combination is supported.
func (t *TPMContext) IsSymmetricAlgorithmSupported(algorithm SymObjectAlgorithmId, keyBits uint16, sessions ...SessionContext) bool {
	params := PublicParams{
		Type: ObjectTypeSymCipher,
		Parameters: &PublicParamsU{
			SymDetail: &SymCipherParams{
				Sym: SymDefObject{
					Algorithm: algorithm,
					KeyBits:   &SymKeyBitsU{Sym: keyBits},
					Mode:      &SymModeU{Sym: SymModeCFB}}}}}
	if err := t.TestParms(&params, sessions...); err != nil {
		return false
	}
	return true
}
