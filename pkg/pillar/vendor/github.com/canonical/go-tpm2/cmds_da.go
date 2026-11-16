// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 25 - Dictionary Attack Functions

// DictionaryAttackLockReset executes the TPM2_DictionaryAttackLockReset command to cancel the
// effect of a TPM lockout. The lockContext parameter must always be a ResourceContext
// corresponding to [HandleLockout]. The command requires authorization with the user auth role
// for lockContext, with session based authorization provided via lockContextAuthSession.
//
// On successful completion, the lockout counter will be reset to zero.
func (t *TPMContext) DictionaryAttackLockReset(lockContext ResourceContext, lockContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandDictionaryAttackLockReset).
		AddHandles(UseResourceContextWithAuth(lockContext, lockContextAuthSession)).
		AddExtraSessions(sessions...).
		Run(nil)
}

// DictionaryAttackParameters executes the TPM2_DictionaryAttackParameters command to change the
// dictionary attack lockout settings. The newMaxTries parameter sets the maximum value of the
// lockout counter before the TPM enters lockout mode. If it is set to zero, then the TPM will
// enter lockout mode and the use of dictionary attack protected entities will be disabled.
// The newRecoveryTime parameter specifies the amount of time in seconds it takes for the lockout
// counter to decrement by one. If it is set to zero, then dictionary attack protection is
// disabled. The lockoutRecovery parameter specifies the amount of time in seconds that the lockout
// hierarchy authorization cannot be used after an authorization failure. If it is set to zero,
// then the lockout hierarchy can be used again after a TPM reset, restart or resume. The
// newRecoveryTime and lockoutRecovery parameters are measured against powered on time rather than
// clock time.
//
// The lockContext parameter must be a ResourceContext corresponding to [HandleLockout]. The
// command requires authorization with the user auth role for lockContext, with session based
// authorization provided via lockContextAuthSession.
func (t *TPMContext) DictionaryAttackParameters(lockContext ResourceContext, newMaxTries, newRecoveryTime, lockoutRecovery uint32, lockContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandDictionaryAttackParameters).
		AddHandles(UseResourceContextWithAuth(lockContext, lockContextAuthSession)).
		AddParams(newMaxTries, newRecoveryTime, lockoutRecovery).
		AddExtraSessions(sessions...).
		Run(nil)
}
