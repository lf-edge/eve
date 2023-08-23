// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/canonical/go-tpm2/ppi"
)

type ppiImpl struct {
	sysfsPath string
	version   string
	ops       map[ppi.OperationId]ppi.OperationStatus
	sta       ppi.StateTransitionAction
}

func (p *ppiImpl) Version() string {
	return p.version
}

func (p *ppiImpl) SubmitOperation(op ppi.OperationId, arg *uint64) error {
	f, err := os.OpenFile(filepath.Join(p.sysfsPath, "request"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	cmd := strconv.FormatUint(uint64(op), 10)
	if arg != nil {
		cmd += " " + strconv.FormatUint(*arg, 10)
	}

	_, err = f.WriteString(cmd)
	switch {
	case errors.Is(err, syscall.EPERM):
		return ppi.ErrOperationUnsupported
	case errors.Is(err, syscall.EFAULT):
		return ppi.ErrOperationFailed
	default:
		return err
	}
}

func (p *ppiImpl) StateTransitionAction() ppi.StateTransitionAction {
	return p.sta
}

func (p *ppiImpl) OperationStatus(op ppi.OperationId) ppi.OperationStatus {
	status, implemented := p.ops[op]
	if !implemented {
		return ppi.OperationNotImplemented
	}
	return status
}

func (p *ppiImpl) OperationResponse() (*ppi.OperationResponse, error) {
	rspBytes, err := ioutil.ReadFile(filepath.Join(p.sysfsPath, "response"))
	if err != nil {
		return nil, err
	}

	rsp := string(rspBytes)

	var arg1, arg2 uint64
	if _, err := fmt.Sscanf(rsp, "%d", &arg1); err != nil {
		return nil, fmt.Errorf("cannot scan response \"%s\": %w", rsp, err)
	}
	if arg1 == 0 {
		return nil, nil
	}

	if _, err := fmt.Sscanf(rsp, "%d%v:", &arg1, &arg2); err != nil {
		return nil, fmt.Errorf("cannot scan response \"%s\": %w", rsp, err)
	}

	r := &ppi.OperationResponse{Operation: ppi.OperationId(arg1)}
	if arg2 != 0 {
		r.Err = ppi.OperationError(arg2)
	}
	return r, nil
}

func newPPI(path string) (*ppiImpl, error) {
	opsFile, err := os.OpenFile(filepath.Join(path, "tcg_operations"), os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer opsFile.Close()

	ops := make(map[ppi.OperationId]ppi.OperationStatus)

	scanner := bufio.NewScanner(opsFile)
	for scanner.Scan() {
		var op ppi.OperationId
		var status ppi.OperationStatus
		if _, err := fmt.Sscanf(scanner.Text(), "%d%d", &op, &status); err != nil {
			return nil, fmt.Errorf("cannot scan operation \"%s\": %w", scanner.Text(), err)
		}

		ops[op] = status
	}

	staBytes, err := ioutil.ReadFile(filepath.Join(path, "transition_action"))
	if err != nil {
		return nil, err
	}

	var sta ppi.StateTransitionAction
	var dummy string
	if _, err := fmt.Sscanf(string(staBytes), "%d:%s\n", &sta, &dummy); err != nil {
		return nil, fmt.Errorf("cannot scan transition action \"%s\": %w", string(staBytes), err)
	}

	versionBytes, err := ioutil.ReadFile(filepath.Join(path, "version"))
	if err != nil {
		return nil, err
	}

	return &ppiImpl{
		sysfsPath: path,
		version:   strings.TrimSpace(string(versionBytes)),
		ops:       ops,
		sta:       sta}, nil
}
