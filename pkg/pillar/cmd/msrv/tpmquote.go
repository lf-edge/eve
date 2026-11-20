// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package msrv

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
	etpm "github.com/lf-edge/eve/pkg/pillar/evetpm"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"golang.org/x/time/rate"
)

const (
	// TpmQuoteBindingDomain prefixes the binding preimage before hashing, so
	// a quote from this API cannot be mistaken for one over other data.
	TpmQuoteBindingDomain = "EVE-MSRV-TPM-QUOTE-V1\x00"
	// TpmQuoteCallerDataMax bounds the caller-supplied bytes in a binding.
	TpmQuoteCallerDataMax = 1024

	// The TPM is shared with tpmmgr, vaultmgr and vcomlink and executes one
	// command at a time; these keep apps from starving them and each other.
	tpmQuotePerIPRate   = rate.Limit(1)
	tpmQuotePerIPBurst  = 5
	tpmQuoteGlobalRate  = rate.Limit(4)
	tpmQuoteGlobalBurst = 8
	tpmQuoteIdleTimeout = 10 * time.Minute
	tpmBusyWait         = 10 * time.Second
	// tpmWriteTimeout replaces the metadata server's 5 s write timeout:
	// tpmBusyWait to get the TPM, then as long for the commands.
	tpmWriteTimeout = 2 * tpmBusyWait
)

// TpmQuoteRequest is the body of POST /eve/v1/tpm/quote.
type TpmQuoteRequest struct {
	// CallerData is bound into the quote, e.g. a key digest or a log
	// checkpoint hash.
	CallerData []byte `json:"caller_data"`
}

// TpmQuoteBinding is the preimage of the quote's qualifyingData:
// SHA-256(TpmQuoteBindingDomain || JSON(TpmQuoteBinding)). msrv fills in
// Caller from the request's source address; the caller cannot choose it.
type TpmQuoteBinding struct {
	Caller     CallerIdentity `json:"caller"`
	CallerData []byte         `json:"caller_data"`
}

// TpmQuoteResponse is the reply to POST /eve/v1/tpm/quote.
type TpmQuoteResponse struct {
	Quote *etpm.AIKQuote `json:"quote"`
	// Binding is the exact preimage hashed into qualifyingData.
	Binding []byte `json:"binding"`
	// TPM part description, repeated from /eve/v1/tpm/identity so a log
	// entry holding only this response names the part.
	Manufacturer    string `json:"manufacturer"`
	Model           string `json:"model"`
	FirmwareVersion string `json:"firmware_version"`
	// EventLog is the raw TCG measured-boot event log behind PCRs 0-9.
	EventLog []byte `json:"event_log,omitempty"`
}

// tpmAttest holds what the TPM quote and identity handlers share.
type tpmAttest struct {
	busy     chan struct{}
	global   *rate.Limiter
	idMu     sync.Mutex
	identity *etpm.TpmIdentity
}

func (msrv *Msrv) tpmAttestState() *tpmAttest {
	msrv.tpmAttestOnce.Do(func() {
		msrv.tpmAttest = &tpmAttest{
			busy:   make(chan struct{}, 1),
			global: rate.NewLimiter(tpmQuoteGlobalRate, tpmQuoteGlobalBurst),
		}
	})
	return msrv.tpmAttest
}

// withTpm serializes TPM access from these handlers and applies the global
// rate limit, so many callers on many IPs cannot monopolize the TPM.
func (ta *tpmAttest) withTpm(ctx context.Context, fn func(rw io.ReadWriter) error) error {
	if !ta.global.Allow() {
		return errTpmBusy
	}
	ctx, cancel := context.WithTimeout(ctx, tpmBusyWait)
	defer cancel()
	select {
	case ta.busy <- struct{}{}:
	case <-ctx.Done():
		return errTpmBusy
	}
	defer func() { <-ta.busy }()
	rw, err := tpm2.OpenTPM(TPMDevicePath)
	if err != nil {
		return fmt.Errorf("opening TPM: %w", err)
	}
	defer rw.Close()
	return fn(rw)
}

var errTpmBusy = errors.New("TPM busy, retry later")

func (ta *tpmAttest) getIdentity(ctx context.Context) (*etpm.TpmIdentity, error) {
	ta.idMu.Lock()
	defer ta.idMu.Unlock()
	if ta.identity != nil {
		return ta.identity, nil
	}
	err := ta.withTpm(ctx, func(rw io.ReadWriter) error {
		id, err := etpm.ReadTpmIdentity(rw)
		if err == nil {
			ta.identity = id
		}
		return err
	})
	return ta.identity, err
}

func tpmErrorStatus(err error) int {
	if errors.Is(err, errTpmBusy) {
		return http.StatusServiceUnavailable
	}
	return http.StatusInternalServerError
}

func writeJSON(w http.ResponseWriter, v any) {
	resp, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(resp)
}

// handleTpmIdentity serves GET /eve/v1/tpm/identity: the TPM part, the EK and
// AIK public areas, and the EK certificates from NV.
func (msrv *Msrv) handleTpmIdentity() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tpmInUse() {
			http.Error(w, "no TPM in use on this device", http.StatusNotFound)
			return
		}
		id, err := msrv.tpmAttestState().getIdentity(r.Context())
		if err != nil {
			msrv.Log.Errorf("handleTpmIdentity: %v", err)
			http.Error(w, err.Error(), tpmErrorStatus(err))
			return
		}
		writeJSON(w, id)
	}
}

// handleTpmQuote serves POST /eve/v1/tpm/quote: an AIK quote of PCRs 0-15
// whose qualifyingData binds the calling workload and the caller's data.
func (msrv *Msrv) handleTpmQuote() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tpmInUse() {
			http.Error(w, "no TPM in use on this device", http.StatusNotFound)
			return
		}
		var req TpmQuoteRequest
		body := http.MaxBytesReader(w, r.Body, 4*TpmQuoteCallerDataMax)
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request body: %v", err), http.StatusBadRequest)
			return
		}
		if len(req.CallerData) > TpmQuoteCallerDataMax {
			http.Error(w, fmt.Sprintf("caller_data exceeds %d bytes",
				TpmQuoteCallerDataMax), http.StatusBadRequest)
			return
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "invalid remote address", http.StatusBadRequest)
			return
		}
		caller, err := msrv.resolveCaller(r.Context(), net.ParseIP(host))
		if err != nil {
			msrv.Log.Warnf("handleTpmQuote: caller %s: %v", host, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		binding, err := json.Marshal(TpmQuoteBinding{Caller: *caller,
			CallerData: req.CallerData})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		qd := sha256.Sum256(append([]byte(TpmQuoteBindingDomain), binding...))

		ta := msrv.tpmAttestState()
		id, err := ta.getIdentity(r.Context())
		if err != nil {
			http.Error(w, err.Error(), tpmErrorStatus(err))
			return
		}
		var quote *etpm.AIKQuote
		err = ta.withTpm(r.Context(), func(rw io.ReadWriter) error {
			var err error
			quote, err = etpm.QuoteWithAIK(rw, qd[:], etpm.PcrListForQuote)
			return err
		})
		if err != nil {
			msrv.Log.Errorf("handleTpmQuote: %v", err)
			http.Error(w, err.Error(), tpmErrorStatus(err))
			return
		}
		resp := TpmQuoteResponse{
			Quote:           quote,
			Binding:         binding,
			Manufacturer:    id.Manufacturer,
			Model:           id.Model,
			FirmwareVersion: id.FirmwareVersion,
		}
		if eventLog, err := os.ReadFile(tpmEventLogPath); err == nil {
			resp.EventLog = eventLog
		} else {
			msrv.Log.Warnf("handleTpmQuote: reading event log: %v", err)
		}
		msrv.Log.Noticef("handleTpmQuote: quote for %s %s", caller.Kind, caller.String())
		writeJSON(w, resp)
	}
}

// TpmActivateRequest is the body of POST /eve/v1/tpm/activate: the output of
// TPM2_MakeCredential for the identity's ek_public and aik_name.
type TpmActivateRequest struct {
	// CredentialBlob is the TPM2B_ID_OBJECT, EncryptedSecret the
	// TPM2B_ENCRYPTED_SECRET, each with its 2-byte size prefix.
	CredentialBlob  []byte `json:"credential_blob"`
	EncryptedSecret []byte `json:"encrypted_secret"`
}

// TpmActivateResponse is the reply to POST /eve/v1/tpm/activate.
type TpmActivateResponse struct {
	Secret []byte `json:"secret"`
}

// tpmActivateBodyMax bounds the request; an RSA-2048 credential is ~600 bytes.
const tpmActivateBodyMax = 8192

// handleTpmActivate serves POST /eve/v1/tpm/activate: TPM2_ActivateCredential
// with the EK from /eve/v1/tpm/identity, so a verifier can check that the AIK
// is in the TPM the EK certificate names.
func (msrv *Msrv) handleTpmActivate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !tpmInUse() {
			http.Error(w, "no TPM in use on this device", http.StatusNotFound)
			return
		}
		var req TpmActivateRequest
		body := http.MaxBytesReader(w, r.Body, tpmActivateBodyMax)
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			http.Error(w, fmt.Sprintf("bad request body: %v", err), http.StatusBadRequest)
			return
		}
		ta := msrv.tpmAttestState()
		id, err := ta.getIdentity(r.Context())
		if err != nil {
			http.Error(w, err.Error(), tpmErrorStatus(err))
			return
		}
		ek, err := tpm2.DecodePublic(id.EKPublic)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		var secret []byte
		err = ta.withTpm(r.Context(), func(rw io.ReadWriter) error {
			var err error
			secret, err = etpm.ActivateCredentialWithTCGEK(rw, ek,
				req.CredentialBlob, req.EncryptedSecret)
			return err
		})
		if err != nil {
			msrv.Log.Warnf("handleTpmActivate: %v", err)
			status := tpmErrorStatus(err)
			if errors.Is(err, etpm.ErrCredentialActivation) {
				status = http.StatusBadRequest
			}
			http.Error(w, err.Error(), status)
			return
		}
		writeJSON(w, TpmActivateResponse{Secret: secret})
	}
}

// Variables so tests can point them elsewhere.
var (
	tpmEventLogPath = types.TpmMeasurementLogFile
	tpmInUse        = etpm.IsTpmEnabled
)
