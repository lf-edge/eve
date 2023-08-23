// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 16 - Random Number Generator

// GetRandom executes the TPM2_GetRandom command to return the requested number of bytes from the
// TPM's random number generator.
func (t *TPMContext) GetRandom(bytesRequested uint16, sessions ...SessionContext) (randomBytes Digest, err error) {
	if err := t.StartCommand(CommandGetRandom).
		AddParams(bytesRequested).
		AddExtraSessions(sessions...).
		Run(nil, &randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

func (t *TPMContext) StirRandom(inData SensitiveData, sessions ...SessionContext) error {
	return t.StartCommand(CommandStirRandom).
		AddParams(inData).
		AddExtraSessions(sessions...).
		Run(nil)
}
