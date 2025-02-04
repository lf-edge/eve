// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 21 - Command Audit

// SetCommandCodeAuditStatus executes the TPM2_SetCommandCodeAuditStatus command to allow the
// privacy administrator or platform to change the audit status of a command, or change the digest
// algorithm used for command auditing (but not both at the same time).
//
// The auth parameter should be a ResourceContext corresponding to either [HandlePlatform] or
// [HandleOwner]. This command requires authorization of auth with the user auth role, with session
// based authorization provided via authAuthSession.
//
// The auditAlg argument specifies the digest algorithm for command auditing. The setList argument
// is used to specify which commands should be added to the list of commands to be audited. The
// clearList argument is used to specify which commands should be removed from the list of commands
// to be audited.
//
// If auditAlg is not [HashAlgorithmNull] or the current audit digest algorithm, and the length of
// setList or clearList is greater than zero, a *[TPMParameterError] error with an error code of
// [ErrorValue] will be returned for parameter index 1.
func (t *TPMContext) SetCommandCodeAuditStatus(auth ResourceContext, auditAlg HashAlgorithmId, setList, clearList CommandCodeList, authAuthSession SessionContext, sessions ...SessionContext) error {
	return t.StartCommand(CommandSetCommandCodeAuditStatus).
		AddHandles(UseResourceContextWithAuth(auth, authAuthSession)).
		AddParams(auditAlg, setList, clearList).
		Run(nil)
}
