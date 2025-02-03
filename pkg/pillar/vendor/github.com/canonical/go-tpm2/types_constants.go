// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/elliptic"
)

// This file contains types defined in section 6 (Contants) in
// part 2 of the library spec.

// TPMGenerated corresponds to the TPM_GENERATED type.
type TPMGenerated uint32

const (
	TPMGeneratedValue TPMGenerated = 0xff544347 // TPM_GENERATED_VALUE
)

// AlgorithmId corresponds to the TPM_ALG_ID type.
type AlgorithmId uint16

const (
	AlgorithmError          AlgorithmId = 0x0000 // TPM_ALG_ERROR
	AlgorithmRSA            AlgorithmId = 0x0001 // TPM_ALG_RSA
	AlgorithmTDES           AlgorithmId = 0x0003 // TPM_ALG_TDES
	AlgorithmSHA1           AlgorithmId = 0x0004 // TPM_ALG_SHA1
	AlgorithmHMAC           AlgorithmId = 0x0005 // TPM_ALG_HMAC
	AlgorithmAES            AlgorithmId = 0x0006 // TPM_ALG_AES
	AlgorithmMGF1           AlgorithmId = 0x0007 // TPM_ALG_MGF1
	AlgorithmKeyedHash      AlgorithmId = 0x0008 // TPM_ALG_KEYEDHASH
	AlgorithmXOR            AlgorithmId = 0x000a // TPM_ALG_XOR
	AlgorithmSHA256         AlgorithmId = 0x000b // TPM_ALG_SHA256
	AlgorithmSHA384         AlgorithmId = 0x000c // TPM_ALG_SHA384
	AlgorithmSHA512         AlgorithmId = 0x000d // TPM_ALG_SHA512
	AlgorithmNull           AlgorithmId = 0x0010 // TPM_ALG_NULL
	AlgorithmSM3_256        AlgorithmId = 0x0012 // TPM_ALG_SM3_256
	AlgorithmSM4            AlgorithmId = 0x0013 // TPM_ALG_SM4
	AlgorithmRSASSA         AlgorithmId = 0x0014 // TPM_ALG_RSASSA
	AlgorithmRSAES          AlgorithmId = 0x0015 // TPM_ALG_RSAES
	AlgorithmRSAPSS         AlgorithmId = 0x0016 // TPM_ALG_RSAPSS
	AlgorithmOAEP           AlgorithmId = 0x0017 // TPM_ALG_OAEP
	AlgorithmECDSA          AlgorithmId = 0x0018 // TPM_ALG_ECDSA
	AlgorithmECDH           AlgorithmId = 0x0019 // TPM_ALG_ECDH
	AlgorithmECDAA          AlgorithmId = 0x001a // TPM_ALG_ECDAA
	AlgorithmSM2            AlgorithmId = 0x001b // TPM_ALG_SM2
	AlgorithmECSchnorr      AlgorithmId = 0x001c // TPM_ALG_ECSCHNORR
	AlgorithmECMQV          AlgorithmId = 0x001d // TPM_ALG_ECMQV
	AlgorithmKDF1_SP800_56A AlgorithmId = 0x0020 // TPM_ALG_KDF1_SP800_56A
	AlgorithmKDF2           AlgorithmId = 0x0021 // TPM_ALG_KDF2
	AlgorithmKDF1_SP800_108 AlgorithmId = 0x0022 // TPM_ALG_KDF1_SP800_108
	AlgorithmECC            AlgorithmId = 0x0023 // TPM_ALG_ECC
	AlgorithmSymCipher      AlgorithmId = 0x0025 // TPM_ALG_SYMCIPHER
	AlgorithmCamellia       AlgorithmId = 0x0026 // TPM_ALG_CAMELLIA
	AlgorithmSHA3_256       AlgorithmId = 0x0027 // TPM_ALG_SHA3_256
	AlgorithmSHA3_384       AlgorithmId = 0x0028 // TPM_ALG_SHA3_384
	AlgorithmSHA3_512       AlgorithmId = 0x0029 // TPM_ALG_SHA3_512
	AlgorithmCTR            AlgorithmId = 0x0040 // TPM_ALG_CTR
	AlgorithmOFB            AlgorithmId = 0x0041 // TPM_ALG_OFB
	AlgorithmCBC            AlgorithmId = 0x0042 // TPM_ALG_CBC
	AlgorithmCFB            AlgorithmId = 0x0043 // TPM_ALG_CFB
	AlgorithmECB            AlgorithmId = 0x0044 // TPM_ALG_ECB

	AlgorithmFirst AlgorithmId = AlgorithmRSA
)

// ECCCurve corresponds to the TPM_ECC_CURVE type.
type ECCCurve uint16

// GoCurve returns the equivalent elliptic.Curve for this ECC curve.
func (c ECCCurve) GoCurve() elliptic.Curve {
	return eccCurves[c]
}

const (
	ECCCurveNIST_P192 ECCCurve = 0x0001 // TPM_ECC_NIST_P192
	ECCCurveNIST_P224 ECCCurve = 0x0002 // TPM_ECC_NIST_P224
	ECCCurveNIST_P256 ECCCurve = 0x0003 // TPM_ECC_NIST_P256
	ECCCurveNIST_P384 ECCCurve = 0x0004 // TPM_ECC_NIST_P384
	ECCCurveNIST_P521 ECCCurve = 0x0005 // TPM_ECC_NIST_P521
	ECCCurveBN_P256   ECCCurve = 0x0010 // TPM_ECC_BN_P256
	ECCCurveBN_P638   ECCCurve = 0x0011 // TPM_ECC_BN_P638
	ECCCurveSM2_P256  ECCCurve = 0x0020 // TPM_ECC_SM2_P256

	ECCCurveFirst ECCCurve = ECCCurveNIST_P192
)

// CommandCode corresponds to the TPM_CC type.
type CommandCode uint32

const (
	CommandFirst CommandCode = 0x0000011A

	CommandNVUndefineSpaceSpecial     CommandCode = 0x0000011F // TPM_CC_NV_UndefineSpaceSpecial
	CommandEvictControl               CommandCode = 0x00000120 // TPM_CC_EvictControl
	CommandHierarchyControl           CommandCode = 0x00000121 // TPM_CC_HierarchyControl
	CommandNVUndefineSpace            CommandCode = 0x00000122 // TPM_CC_NV_UndefineSpace
	CommandClear                      CommandCode = 0x00000126 // TPM_CC_Clear
	CommandClearControl               CommandCode = 0x00000127 // TPM_CC_ClearControl
	CommandClockSet                   CommandCode = 0x00000128 // TPM_CC_ClockSet
	CommandHierarchyChangeAuth        CommandCode = 0x00000129 // TPM_CC_HierarchyChangeAuth
	CommandNVDefineSpace              CommandCode = 0x0000012A // TPM_CC_NV_DefineSpace
	CommandPCRAllocate                CommandCode = 0x0000012B // TPM_CC_PCR_Allocate
	CommandSetPrimaryPolicy           CommandCode = 0x0000012E // TPM_CC_SetPrimaryPolicy
	CommandClockRateAdjust            CommandCode = 0x00000130 // TPM_CC_ClockRateAdjust
	CommandCreatePrimary              CommandCode = 0x00000131 // TPM_CC_CreatePrimary
	CommandNVGlobalWriteLock          CommandCode = 0x00000132 // TPM_CC_NV_GlobalWriteLock
	CommandGetCommandAuditDigest      CommandCode = 0x00000133 // TPM_CC_GetCommandAuditDigest
	CommandNVIncrement                CommandCode = 0x00000134 // TPM_CC_NV_Increment
	CommandNVSetBits                  CommandCode = 0x00000135 // TPM_CC_NV_SetBits
	CommandNVExtend                   CommandCode = 0x00000136 // TPM_CC_NV_Extend
	CommandNVWrite                    CommandCode = 0x00000137 // TPM_CC_NV_Write
	CommandNVWriteLock                CommandCode = 0x00000138 // TPM_CC_NV_WriteLock
	CommandDictionaryAttackLockReset  CommandCode = 0x00000139 // TPM_CC_DictionaryAttackLockReset
	CommandDictionaryAttackParameters CommandCode = 0x0000013A // TPM_CC_DictionaryAttackParameters
	CommandNVChangeAuth               CommandCode = 0x0000013B // TPM_CC_NV_ChangeAuth
	CommandPCREvent                   CommandCode = 0x0000013C // TPM_CC_PCR_Event
	CommandPCRReset                   CommandCode = 0x0000013D // TPM_CC_PCR_Reset
	CommandSequenceComplete           CommandCode = 0x0000013E // TPM_CC_SequenceComplete
	CommandSetCommandCodeAuditStatus  CommandCode = 0x00000140 // TPM_CC_SetCommandCodeAuditStatus
	CommandIncrementalSelfTest        CommandCode = 0x00000142 // TPM_CC_IncrementalSelfTest
	CommandSelfTest                   CommandCode = 0x00000143 // TPM_CC_SelfTest
	CommandStartup                    CommandCode = 0x00000144 // TPM_CC_Startup
	CommandShutdown                   CommandCode = 0x00000145 // TPM_CC_Shutdown
	CommandStirRandom                 CommandCode = 0x00000146 // TPM_CC_StirRandom
	CommandActivateCredential         CommandCode = 0x00000147 // TPM_CC_ActivateCredential
	CommandCertify                    CommandCode = 0x00000148 // TPM_CC_Certify
	CommandPolicyNV                   CommandCode = 0x00000149 // TPM_CC_PolicyNV
	CommandCertifyCreation            CommandCode = 0x0000014A // TPM_CC_CertifyCreation
	CommandDuplicate                  CommandCode = 0x0000014B // TPM_CC_Duplicate
	CommandGetTime                    CommandCode = 0x0000014C // TPM_CC_GetTime
	CommandGetSessionAuditDigest      CommandCode = 0x0000014D // TPM_CC_GetSessionAuditDigest
	CommandNVRead                     CommandCode = 0x0000014E // TPM_CC_NV_Read
	CommandNVReadLock                 CommandCode = 0x0000014F // TPM_CC_NV_ReadLock
	CommandObjectChangeAuth           CommandCode = 0x00000150 // TPM_CC_ObjectChangeAuth
	CommandPolicySecret               CommandCode = 0x00000151 // TPM_CC_PolicySecret
	CommandCreate                     CommandCode = 0x00000153 // TPM_CC_Create
	CommandECDHZGen                   CommandCode = 0x00000154 // TPM_CC_ECDH_ZGen
	CommandHMAC                       CommandCode = 0x00000155 // TPM_CC_HMAC
	CommandImport                     CommandCode = 0x00000156 // TPM_CC_Import
	CommandLoad                       CommandCode = 0x00000157 // TPM_CC_Load
	CommandQuote                      CommandCode = 0x00000158 // TPM_CC_Quote
	CommandRSADecrypt                 CommandCode = 0x00000159 // TPM_CC_RSA_Decrypt
	CommandHMACStart                  CommandCode = 0x0000015B // TPM_CC_HMAC_Start
	CommandSequenceUpdate             CommandCode = 0x0000015C // TPM_CC_SequenceUpdate
	CommandSign                       CommandCode = 0x0000015D // TPM_CC_Sign
	CommandUnseal                     CommandCode = 0x0000015E // TPM_CC_Unseal
	CommandPolicySigned               CommandCode = 0x00000160 // TPM_CC_PolicySigned
	CommandContextLoad                CommandCode = 0x00000161 // TPM_CC_ContextLoad
	CommandContextSave                CommandCode = 0x00000162 // TPM_CC_ContextSave
	CommandECDHKeyGen                 CommandCode = 0x00000163 // TPM_CC_ECDH_KeyGen
	CommandFlushContext               CommandCode = 0x00000165 // TPM_CC_FlushContext
	CommandLoadExternal               CommandCode = 0x00000167 // TPM_CC_LoadExternal
	CommandMakeCredential             CommandCode = 0x00000168 // TPM_CC_MakeCredential
	CommandNVReadPublic               CommandCode = 0x00000169 // TPM_CC_NV_ReadPublic
	CommandPolicyAuthorize            CommandCode = 0x0000016A // TPM_CC_PolicyAuthorize
	CommandPolicyAuthValue            CommandCode = 0x0000016B // TPM_CC_PolicyAuthValue
	CommandPolicyCommandCode          CommandCode = 0x0000016C // TPM_CC_PolicyCommandCode
	CommandPolicyCounterTimer         CommandCode = 0x0000016D // TPM_CC_PolicyCounterTimer
	CommandPolicyCpHash               CommandCode = 0x0000016E // TPM_CC_PolicyCpHash
	CommandPolicyLocality             CommandCode = 0x0000016F // TPM_CC_PolicyLocality
	CommandPolicyNameHash             CommandCode = 0x00000170 // TPM_CC_PolicyNameHash
	CommandPolicyOR                   CommandCode = 0x00000171 // TPM_CC_PolicyOR
	CommandPolicyTicket               CommandCode = 0x00000172 // TPM_CC_PolicyTicket
	CommandReadPublic                 CommandCode = 0x00000173 // TPM_CC_ReadPublic
	CommandRSAEncrypt                 CommandCode = 0x00000174 // TPM_CC_RSA_Encrypt
	CommandStartAuthSession           CommandCode = 0x00000176 // TPM_CC_StartAuthSession
	CommandVerifySignature            CommandCode = 0x00000177 // TPM_CC_VerifySignature
	CommandECCParameters              CommandCode = 0x00000178 // TPM_CC_ECC_Parameters
	CommandGetCapability              CommandCode = 0x0000017A // TPM_CC_GetCapability
	CommandGetRandom                  CommandCode = 0x0000017B // TPM_CC_GetRandom
	CommandGetTestResult              CommandCode = 0x0000017C // TPM_CC_GetTestResult
	CommandHash                       CommandCode = 0x0000017D // TPM_CC_Hash
	CommandPCRRead                    CommandCode = 0x0000017E // TPM_CC_PCR_Read
	CommandPolicyPCR                  CommandCode = 0x0000017F // TPM_CC_PolicyPCR
	CommandPolicyRestart              CommandCode = 0x00000180 // TPM_CC_PolicyRestart
	CommandReadClock                  CommandCode = 0x00000181 // TPM_CC_ReadClock
	CommandPCRExtend                  CommandCode = 0x00000182 // TPM_CC_PCR_Extend
	CommandNVCertify                  CommandCode = 0x00000184 // TPM_CC_NV_Certify
	CommandEventSequenceComplete      CommandCode = 0x00000185 // TPM_CC_EventSequenceComplete
	CommandHashSequenceStart          CommandCode = 0x00000186 // TPM_CC_HashSequenceStart
	CommandPolicyDuplicationSelect    CommandCode = 0x00000188 // TPM_CC_PolicyDuplicationSelect
	CommandPolicyGetDigest            CommandCode = 0x00000189 // TPM_CC_PolicyGetDigest
	CommandTestParms                  CommandCode = 0x0000018A // TPM_CC_TestParms
	CommandCommit                     CommandCode = 0x0000018B // TPM_CC_Commit
	CommandPolicyPassword             CommandCode = 0x0000018C // TPM_CC_PolicyPassword
	CommandPolicyNvWritten            CommandCode = 0x0000018F // TPM_CC_PolicyNvWritten
	CommandPolicyTemplate             CommandCode = 0x00000190 // TPM_CC_PolicyTemplate
	CommandCreateLoaded               CommandCode = 0x00000191 // TPM_CC_CreateLoaded
	CommandPolicyAuthorizeNV          CommandCode = 0x00000192 // TPM_CC_PolicyAuthorizeNV
)

// ResponseCode corresponds to the TPM_RC type.
type ResponseCode uint32

const (
	// The lower 7-bits of format-zero error codes are the error number.
	responseCodeE0 ResponseCode = 0x7f

	// The lower 6-bits of format-one error codes are the error number.
	responseCodeE1 ResponseCode = 0x3f

	// Bit 6 of format-one errors is zero for errors associated with a handle
	// or session, or one for errors associated with a parameter.
	responseCodeP ResponseCode = 1 << 6

	// Bit 7 indicates whether the error is a format-zero (0) or format-one code (1)
	responseCodeF ResponseCode = 1 << 7

	// Bit 8 of format-zero errors is zero for TPM1.2 errors and one for TPM2 errors.
	responseCodeV ResponseCode = 1 << 8

	// Bit 10 of format-zero errors is zero for TCG defined errors and one for vendor
	// defined error.
	responseCodeT ResponseCode = 1 << 10

	// Bit 11 of format-zero errors is zero for errors and one for warnings.
	responseCodeS ResponseCode = 1 << 11

	responseCodeIndex      uint8 = 0xf
	responseCodeIndexShift uint8 = 8

	// Bits 8 to 11 of format-one errors represent the parameter number if P is set
	// or the handle or session number otherwise.
	responseCodeN ResponseCode = ResponseCode(responseCodeIndex) << responseCodeIndexShift
)

// E returns the E field of the response code, corresponding to the error number.
func (rc ResponseCode) E() uint8 {
	if rc.F() {
		return uint8(rc & responseCodeE1)
	}
	return uint8(rc & responseCodeE0)
}

// F returns the F field of the response code, corresponding to the format.
// If it is set, this is a format-one response code. If it is not set, this
// is a format-zero response code.
func (rc ResponseCode) F() bool {
	return rc&responseCodeF != 0
}

// V returns the V field of the response code, corresponding to the version
// and is only relevant for format-zero response codes. If this is set
// then it is a TPM2 code returned when the response tag is
// TPM_ST_NO_SESSIONS. If it is not set then it is a TPM1.2 code returned
// when the response tag is TPM_TAG_RSP_COMMAND.
//
// This will panic if the F field is set.
func (rc ResponseCode) V() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&responseCodeV != 0
}

// T returns the T field of the response code, corresponding to the
// TCG/Vendor indicator and is only relevant for format-zero response
// codes. If this is set then the code is defined by the TPM vendor. If
// it is not set then the code is defined by the TCG.
//
// This will panic if the F field is set.
func (rc ResponseCode) T() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&responseCodeT != 0
}

// S returns the S field of the response code, corresponding to the
// severity and is only relevant for format-zero response codes. If this
// is set then the code indicates a warning. If it is not set then the
// code indicates an error.
//
// This will panic if the F field is set.
func (rc ResponseCode) S() bool {
	if rc.F() {
		panic("not a format-0 response code")
	}
	return rc&responseCodeS != 0
}

// P returns the P field of the response code and is only relevant for
// format-one response codes. If this is set then the code is associated with
// a command parameter. If it is not set then the code is associated with a
// command handle or session.
//
// This will panic if the F field is not set.
func (rc ResponseCode) P() bool {
	if !rc.F() {
		panic("not a format-1 response code")
	}
	return rc&responseCodeP != 0
}

// N returns the N field of the response code and is only relevant for
// format-one response codes. If the P field is set then this indicates the
// parameter number from 0x1 to 0xf. If the P field is not set then the
// lower 3 bits indicate the handle or session number (0x1 to 0x7 for handles
// and 0x9 to 0xf for sessions).
//
// This will panic if the F field is not set.
func (rc ResponseCode) N() uint8 {
	if !rc.F() {
		panic("not a format-1 response code")
	}
	return uint8(rc & responseCodeN >> responseCodeIndexShift)
}

const (
	ResponseSuccess ResponseCode = 0
	ResponseBadTag  ResponseCode = 0x1e
)

// ArithmeticOp corresponds to the TPM_EO type.
type ArithmeticOp uint16

const (
	OpEq         ArithmeticOp = 0x0000 // TPM_EO_EQ
	OpNeq        ArithmeticOp = 0x0001 // TPM_EO_NEQ
	OpSignedGT   ArithmeticOp = 0x0002 // TPM_EO_SIGNED_GT
	OpUnsignedGT ArithmeticOp = 0x0003 // TPM_EO_UNSIGNED_GT
	OpSignedLT   ArithmeticOp = 0x0004 // TPM_EO_SIGNED_LT
	OpUnsignedLT ArithmeticOp = 0x0005 // TPM_EO_UNSIGNED_LT
	OpSignedGE   ArithmeticOp = 0x0006 // TPM_EO_SIGNED_GE
	OpUnsignedGE ArithmeticOp = 0x0007 // TPM_EO_UNSIGNED_GE
	OpSignedLE   ArithmeticOp = 0x0008 // TPM_EO_SIGNED_LE
	OpUnsignedLE ArithmeticOp = 0x0009 // TPM_EO_UNSIGNED_LE
	OpBitset     ArithmeticOp = 0x000a // TPM_EO_BITSET
	OpBitclear   ArithmeticOp = 0x000b // TPM_EO_BITCLEAR
)

// StructTag corresponds to the TPM_ST type.
type StructTag uint16

const (
	TagRspCommand StructTag = 0x00c4 // TPM_ST_RSP_COMMAND

	TagNoSessions         StructTag = 0x8001 // TPM_ST_NO_SESSIONS
	TagSessions           StructTag = 0x8002 // TPM_ST_SESSIONS
	TagAttestNV           StructTag = 0x8014 // TPM_ST_ATTEST_NV
	TagAttestCommandAudit StructTag = 0x8015 // TPM_ST_ATTEST_COMMAND_AUDIT
	TagAttestSessionAudit StructTag = 0x8016 // TPM_ST_ATTEST_SESSION_AUDIT
	TagAttestCertify      StructTag = 0x8017 // TPM_ST_ATTEST_CERTIFY
	TagAttestQuote        StructTag = 0x8018 // TPM_ST_ATTEST_QUOTE
	TagAttestTime         StructTag = 0x8019 // TPM_ST_ATTEST_TIME
	TagAttestCreation     StructTag = 0x801a // TPM_ST_ATTEST_CREATION
	TagCreation           StructTag = 0x8021 // TPM_ST_CREATION
	TagVerified           StructTag = 0x8022 // TPM_ST_VERIFIED
	TagAuthSecret         StructTag = 0x8023 // TPM_ST_AUTH_SECRET
	TagHashcheck          StructTag = 0x8024 // TPM_ST_HASHCHECK
	TagAuthSigned         StructTag = 0x8025 // TPM_ST_AUTH_SIGNED
)

// StartupType corresponds to the TPM_SU type.
type StartupType uint16

const (
	StartupClear StartupType = iota
	StartupState
)

// SessionType corresponds to the TPM_SE type.
type SessionType uint8

const (
	SessionTypeHMAC   SessionType = 0x00 // TPM_SE_HMAC
	SessionTypePolicy SessionType = 0x01 // TPM_SE_POLICY
	SessionTypeTrial  SessionType = 0x03 // TPM_SE_TRIAL
)

// Capability corresponds to the TPM_CAP type.
type Capability uint32

const (
	CapabilityAlgs          Capability = 0 // TPM_CAP_ALGS
	CapabilityHandles       Capability = 1 // TPM_CAP_HANDLES
	CapabilityCommands      Capability = 2 // TPM_CAP_COMMANDS
	CapabilityPPCommands    Capability = 3 // TPM_CAP_PP_COMMANDS
	CapabilityAuditCommands Capability = 4 // TPM_CAP_AUDIT_COMMANDS
	CapabilityPCRs          Capability = 5 // TPM_CAP_PCRS
	CapabilityTPMProperties Capability = 6 // TPM_CAP_TPM_PROPERTIES
	CapabilityPCRProperties Capability = 7 // TPM_CAP_PCR_PROPERTIES
	CapabilityECCCurves     Capability = 8 // TPM_CAP_ECC_CURVES
	CapabilityAuthPolicies  Capability = 9 // TPM_CAP_AUTH_POLICIES
)

// Property corresponds to the TPM_PT type.
type Property uint32

const (
	// These constants represent properties that only change when the firmware in the TPM changes.
	PropertyFamilyIndicator   Property = 0x100 // TPM_PT_FAMILY_INDICATOR
	PropertyLevel             Property = 0x101 // TPM_PT_LEVEL
	PropertyRevision          Property = 0x102 // TPM_PT_REVISION
	PropertyDayOfYear         Property = 0x103 // TPM_PT_DAY_OF_YEAR
	PropertyYear              Property = 0x104 // TPM_PT_YEAR
	PropertyManufacturer      Property = 0x105 // TPM_PT_MANUFACTURER
	PropertyVendorString1     Property = 0x106 // TPM_PT_VENDOR_STRING_1
	PropertyVendorString2     Property = 0x107 // TPM_PT_VENDOR_STRING_2
	PropertyVendorString3     Property = 0x108 // TPM_PT_VENDOR_STRING_3
	PropertyVendorString4     Property = 0x109 // TPM_PT_VENDOR_STRING_4
	PropertyVendorTPMType     Property = 0x10a // TPM_PT_VENDOR_TPM_TYPE
	PropertyFirmwareVersion1  Property = 0x10b // TPM_PT_FIRMWARE_VERSION_1
	PropertyFirmwareVersion2  Property = 0x10c // TPM_PT_FIRMWARE_VERSION_2
	PropertyInputBuffer       Property = 0x10d // TPM_PT_INPUT_BUFFER
	PropertyHRTransientMin    Property = 0x10e // TPM_PT_HR_TRANSIENT_MIN
	PropertyHRPersistentMin   Property = 0x10f // TPM_PT_HR_PERSISTENT_MIN
	PropertyHRLoadedMin       Property = 0x110 // TPM_PT_HR_LOADED_MIN
	PropertyActiveSessionsMax Property = 0x111 // TPM_PT_ACTIVE_SESSIONS_MAX
	PropertyPCRCount          Property = 0x112 // TPM_PT_PCR_COUNT
	PropertyPCRSelectMin      Property = 0x113 // TPM_PT_PCR_SELECT_MIN
	PropertyContextGapMax     Property = 0x114 // TPM_PT_CONTEXT_GAP_MAX
	PropertyNVCountersMax     Property = 0x116 // TPM_PT_NV_COUNTERS_MAX
	PropertyNVIndexMax        Property = 0x117 // TPM_PT_NV_INDEX_MAX
	PropertyMemory            Property = 0x118 // TPM_PT_MEMORY
	PropertyClockUpdate       Property = 0x119 // TPM_PT_CLOCK_UPDATE
	PropertyContextHash       Property = 0x11a // TPM_PT_CONTEXT_HASH
	PropertyContextSym        Property = 0x11b // TPM_PT_CONTEXT_SYM
	PropertyContextSymSize    Property = 0x11c // TPM_PT_CONTEXT_SYM_SIZE
	PropertyOrderlyCount      Property = 0x11d // TPM_PT_ORDERLY_COUNT
	PropertyMaxCommandSize    Property = 0x11e // TPM_PT_MAX_COMMAND_SIZE
	PropertyMaxResponseSize   Property = 0x11f // TPM_PT_MAX_RESPONSE_SIZE
	PropertyMaxDigest         Property = 0x120 // TPM_PT_MAX_DIGEST
	PropertyMaxObjectContext  Property = 0x121 // TPM_PT_MAX_OBJECT_CONTEXT
	PropertyMaxSessionContext Property = 0x122 // TPM_PT_MAX_SESSION_CONTEXT
	PropertyPSFamilyIndicator Property = 0x123 // TPM_PT_PS_FAMILY_INDICATOR
	PropertyPSLevel           Property = 0x124 // TPM_PT_PS_LEVEL
	PropertyPSRevision        Property = 0x125 // TPM_PT_PS_REVISION
	PropertyPSDayOfYear       Property = 0x126 // TPM_PT_PS_DAY_OF_YEAR
	PropertyPSYear            Property = 0x127 // TPM_PT_PS_YEAR
	PropertySplitMax          Property = 0x128 // TPM_PT_SPLIT_MAX
	PropertyTotalCommands     Property = 0x129 // TPM_PT_TOTAL_COMMANDS
	PropertyLibraryCommands   Property = 0x12a // TPM_PT_LIBRARY_COMMANDS
	PropertyVendorCommands    Property = 0x12b // TPM_PT_VENDOR_COMMANDS
	PropertyNVBufferMax       Property = 0x12c // TPM_PT_NV_BUFFER_MAX
	PropertyModes             Property = 0x12d // TPM_PT_MODES
	PropertyMaxCapBuffer      Property = 0x12e // TPM_PT_MAX_CAP_BUFFER

	PropertyFixed Property = PropertyFamilyIndicator
)

const (
	// These constants represent properties that change for reasons other than a firmware upgrade. Some of
	// them may not persist across power cycles.
	PropertyPermanent         Property = 0x200 // TPM_PT_PERMANENT
	PropertyStartupClear      Property = 0x201 // TPM_PT_STARTUP_CLEAR
	PropertyHRNVIndex         Property = 0x202 // TPM_PT_HR_NV_INDEX
	PropertyHRLoaded          Property = 0x203 // TPM_PT_HR_LOADED
	PropertyHRLoadedAvail     Property = 0x204 // TPM_PT_HR_LOADED_AVAIL
	PropertyHRActive          Property = 0x205 // TPM_PT_HR_ACTIVE
	PropertyHRActiveAvail     Property = 0x206 // TPM_PT_HR_ACTIVE_AVAIL
	PropertyHRTransientAvail  Property = 0x207 // TPM_PT_HR_TRANSIENT_AVAIL
	PropertyHRPersistent      Property = 0x208 // TPM_PT_HR_PERSISTENT
	PropertyHRPersistentAvail Property = 0x209 // TPM_PT_HR_PERSISTENT_AVAIL
	PropertyNVCounters        Property = 0x20a // TPM_PT_NV_COUNTERS
	PropertyNVCountersAvail   Property = 0x20b // TPM_PT_NV_COUNTERS_AVAIL
	PropertyAlgorithmSet      Property = 0x20c // TPM_PT_ALGORITHM_SET
	PropertyLoadedCurves      Property = 0x20d // TPM_PT_LOADED_CURVES
	PropertyLockoutCounter    Property = 0x20e // TPM_PT_LOCKOUT_COUNTER
	PropertyMaxAuthFail       Property = 0x20f // TPM_PT_MAX_AUTH_FAIL
	PropertyLockoutInterval   Property = 0x210 // TPM_PT_LOCKOUT_INTERVAL
	PropertyLockoutRecovery   Property = 0x211 // TPM_PT_LOCKOUT_RECOVERY
	PropertyNVWriteRecovery   Property = 0x212 // TPM_PT_NV_WRITE_RECOVERY
	PropertyAuditCounter0     Property = 0x213 // TPM_PT_AUDIT_COUNTER_0
	PropertyAuditCounter1     Property = 0x214 // TPM_PT_AUDIT_COUNTER_1

	PropertyVar Property = PropertyPermanent
)

// PropertyPCR corresponds to the TPM_PT_PCR type.
type PropertyPCR uint32

const (
	PropertyPCRSave        PropertyPCR = 0x00 // TPM_PT_PCR_SAVE
	PropertyPCRExtendL0    PropertyPCR = 0x01 // TPM_PT_PCR_EXTEND_L0
	PropertyPCRResetL0     PropertyPCR = 0x02 // TPM_PT_PCR_RESET_L0
	PropertyPCRExtendL1    PropertyPCR = 0x03 // TPM_PT_PCR_EXTEND_L1
	PropertyPCRResetL1     PropertyPCR = 0x04 // TPM_PT_PCR_RESET_L1
	PropertyPCRExtendL2    PropertyPCR = 0x05 // TPM_PT_PCR_EXTEND_L2
	PropertyPCRResetL2     PropertyPCR = 0x06 // TPM_PT_PCR_RESET_L2
	PropertyPCRExtendL3    PropertyPCR = 0x07 // TPM_PT_PCR_EXTEND_L3
	PropertyPCRResetL3     PropertyPCR = 0x08 // TPM_PT_PCR_RESET_L3
	PropertyPCRExtendL4    PropertyPCR = 0x09 // TPM_PT_PCR_EXTEND_L4
	PropertyPCRResetL4     PropertyPCR = 0x0a // TPM_PT_PCR_RESET_L4
	PropertyPCRNoIncrement PropertyPCR = 0x11 // TPM_PT_PCR_NO_INCREMENT
	PropertyPCRDRTMReset   PropertyPCR = 0x12 // TPM_PT_PCR_DRTM_RESET
	PropertyPCRPolicy      PropertyPCR = 0x13 // TPM_PT_PCR_POLICY
	PropertyPCRAuth        PropertyPCR = 0x14 // TPM_PT_PCR_AUTH

	PropertyPCRFirst PropertyPCR = PropertyPCRSave
)
