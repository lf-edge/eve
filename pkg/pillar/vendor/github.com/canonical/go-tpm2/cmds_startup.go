// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 10 - Testing

// Startup executes the TPM2_Startup command with the specified StartupType. If this isn't preceded
// by _TPM_Init then it will return a *[TPMError] error with an error code of [ErrorInitialize].
// The shutdown and startup sequence determines how the TPM responds to this call:
//   - A call with startupType == [StartupClear] preceded by a call to [TPMContext.Shutdown] with
//     shutdownType == [StartupClear] or without a preceding call to [TPMContext.Shutdown] will
//     cause a TPM reset.
//   - A call with startupType == [StartupClear] preceded by a call to [TPMContext.Shutdown] with
//     shutdownType == [StartupState] will cause a TPM restart.
//   - A call with startupType == [StartupState] preceded by a call to [TPMContext.Shutdown] with
//     shutdownType == [StartupState] will cause a TPM resume.
//   - A call with startupType == [StartupState] that isn't preceded by a call to
//     [TPMContext.Shutdown] with shutdownType == [StartupState] will fail with a
//     *[TPMParameterError] error with an error code of [ErrorValue].
//
// If called with startupType == [StartupState], a *[TPMError] error with an error code of
// [ErrorNVUninitialized] will be returned if the saved state cannot be recovered. In this case,
// the function must be called with startupType == [StartupClear].
//
// Subsequent use of HandleContext instances corresponding to entities that are evicted as a
// consequence of this function will no longer work.
func (t *TPMContext) Startup(startupType StartupType) error {
	return t.StartCommand(CommandStartup).AddParams(startupType).Run(nil)
}

// Shutdown executes the TPM2_Shutdown command with the specified StartupType, and is used to
// prepare the TPM for a power cycle. Calling this with shutdownType == [StartupClear] prepares the
// TPM for a TPM reset. Calling it with shutdownType == [StartupState] prepares the TPM for either
// a TPM restart or TPM resume, depending on how [TPMContext.Startup] is called. Some commands
// executed after [TPMContext.Shutdown] but before a power cycle will nullify the effect of this
// function.
//
// If a PCR bank has been reconfigured and shutdownType == [StartupState], a *[TPMParameterError]
// error with an error code of [ErrorType] will be returned.
func (t *TPMContext) Shutdown(shutdownType StartupType, sessions ...SessionContext) error {
	return t.StartCommand(CommandShutdown).AddParams(shutdownType).AddExtraSessions(sessions...).Run(nil)
}
