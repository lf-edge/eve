// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"

	internal_crypt "github.com/canonical/go-tpm2/internal/crypt"
	"github.com/canonical/go-tpm2/mu"
)

func isParamEncryptable(param interface{}) bool {
	return mu.DetermineTPMKind(param) == mu.TPMKindSized
}

func (s *sessionParam) ComputeSessionValue() []byte {
	var key []byte
	key = append(key, s.Session.Data().SessionKey...)
	if s.IsAuth() {
		key = append(key, s.AssociatedResource.GetAuthValue()...)
	}
	return key
}

func (p *sessionParams) decryptSession() (*sessionParam, int) {
	if p.DecryptSessionIndex == -1 {
		return nil, -1
	}
	return p.Sessions[p.DecryptSessionIndex], p.DecryptSessionIndex
}

func (p *sessionParams) encryptSession() (*sessionParam, int) {
	if p.EncryptSessionIndex == -1 {
		return nil, -1
	}
	return p.Sessions[p.EncryptSessionIndex], p.EncryptSessionIndex
}

func (p *sessionParams) hasDecryptSession() bool {
	return p.DecryptSessionIndex != -1
}

func (p *sessionParams) ComputeEncryptNonce() {
	s, i := p.encryptSession()
	if s == nil || i == 0 || !p.Sessions[0].IsAuth() {
		return
	}
	ds, di := p.decryptSession()
	if ds != nil && di == i {
		return
	}

	p.Sessions[0].EncryptNonce = s.Session.NonceTPM()
}

func (p *sessionParams) EncryptCommandParameter(cpBytes []byte) error {
	s, i := p.decryptSession()
	if s == nil {
		return nil
	}

	sessionData := s.Session.Data()
	hashAlg := sessionData.HashAlg

	sessionValue := s.ComputeSessionValue()

	size := binary.BigEndian.Uint16(cpBytes)
	data := cpBytes[2 : size+2]

	symmetric := sessionData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		if symmetric.Mode.Sym != SymModeCFB {
			return errors.New("unsupported cipher mode")
		}
		k := internal_crypt.KDFa(hashAlg.GetHash(), sessionValue, []byte(CFBKey), sessionData.NonceCaller, sessionData.NonceTPM,
			int(symmetric.KeyBits.Sym)+(aes.BlockSize*8))
		offset := (symmetric.KeyBits.Sym + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := internal_crypt.SymmetricEncrypt(symmetric.Algorithm, symKey, iv, data); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		internal_crypt.XORObfuscation(hashAlg.GetHash(), sessionValue, sessionData.NonceCaller, sessionData.NonceTPM, data)
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	if i > 0 && p.Sessions[0].IsAuth() {
		p.Sessions[0].DecryptNonce = sessionData.NonceTPM
	}

	return nil
}

func (p *sessionParams) DecryptResponseParameter(rpBytes []byte) error {
	s, _ := p.encryptSession()
	if s == nil {
		return nil
	}

	sessionData := s.Session.Data()
	hashAlg := sessionData.HashAlg

	sessionValue := s.ComputeSessionValue()

	size := binary.BigEndian.Uint16(rpBytes)
	data := rpBytes[2 : size+2]

	symmetric := sessionData.Symmetric

	switch symmetric.Algorithm {
	case SymAlgorithmAES:
		if symmetric.Mode.Sym != SymModeCFB {
			return errors.New("unsupported cipher mode")
		}
		k := internal_crypt.KDFa(hashAlg.GetHash(), sessionValue, []byte(CFBKey), sessionData.NonceTPM, sessionData.NonceCaller,
			int(symmetric.KeyBits.Sym)+(aes.BlockSize*8))
		offset := (symmetric.KeyBits.Sym + 7) / 8
		symKey := k[0:offset]
		iv := k[offset:]
		if err := internal_crypt.SymmetricDecrypt(symmetric.Algorithm, symKey, iv, data); err != nil {
			return fmt.Errorf("AES encryption failed: %v", err)
		}
	case SymAlgorithmXOR:
		internal_crypt.XORObfuscation(hashAlg.GetHash(), sessionValue, sessionData.NonceTPM, sessionData.NonceCaller, data)
	default:
		return fmt.Errorf("unknown symmetric algorithm: %v", symmetric.Algorithm)
	}

	return nil
}
