package hypervisor

import (
	"encoding/json"
	"github.com/digitalocean/go-qemu/qmp"
	"time"
)

// this package implements subset of
//     https://qemu.weilnetz.de/doc/qemu-qmp-ref.html

const sockTimeout = 10 * time.Second

func execRawCmd(socket, cmd string) ([]byte, error) {
	monitor, err := qmp.NewSocketMonitor("unix", socket, sockTimeout)
	if err != nil {
		return nil, err
	}

	if err := monitor.Connect(); err != nil {
		return nil, err
	}
	defer monitor.Disconnect()

	return monitor.Run([]byte(cmd))
}

func execContinue(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "cont" }`)
	return err
}

func execStop(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "stop" }`)
	return err
}

func execShutdown(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "system_powerdown" }`)
	return err
}

func execQuit(socket string) error {
	_, err := execRawCmd(socket, `{ "execute": "quit" }`)
	return err
}

func execQueryCLIOptions(socket string) (string, error) {
	res, err := execRawCmd(socket, `{ "execute": "query-command-line-options" }`)
	return string(res), err
}

func getQemuStatus(socket string) (string, error) {
	if raw, err := execRawCmd(socket, `{ "execute": "query-status" }`); err == nil {
		var result struct {
			ID     string `json:"id"`
			Return struct {
				Running    bool   `json:"running"`
				Singlestep bool   `json:"singlestep"`
				Status     string `json:"status"`
			} `json:"return"`
		}
		err = json.Unmarshal(raw, &result)
		return result.Return.Status, err
	} else {
		return "", err
	}
}
