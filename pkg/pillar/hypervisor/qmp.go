package hypervisor

import (
	"encoding/json"
	"fmt"
	"github.com/digitalocean/go-qemu/qmp"
	"github.com/sirupsen/logrus"
	"os"
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

func execVNCPassword(socket string, password string) error {
	vncSetPwd := fmt.Sprintf(`{ "execute": "change-vnc-password", "arguments": { "password": "%s" } }`, password)
	_, err := execRawCmd(socket, vncSetPwd)
	return err
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

func qmpEventHandler(listenerSocket, executorSocket string) {
	monitor, err := qmp.NewSocketMonitor("unix", listenerSocket, sockTimeout)
	if err != nil {
		logrus.Errorf("qmpEventHandler: Exception while getting monitor of listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	if err := monitor.Connect(); err != nil {
		logrus.Errorf("qmpEventHandler: Exception while connecting listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	defer monitor.Disconnect()

	eventChan, err := monitor.Events()
	if err != nil {
		logrus.Errorf("qmpEventHandler: Exception while getting event channel from listenerSocket: %s. %s", listenerSocket, err.Error())
		return
	}
	for {
		if _, err := os.Stat(listenerSocket); err != nil {
			logrus.Errorf("qmpEventHandler: Exception while accessing listenerSocket: %s. %s", listenerSocket, err.Error())
			return
		}
		select {
		case event := <-eventChan:
			switch event.Event {
			case "SHUTDOWN":
				logrus.Infof("qmpEventHandler: Received event: %s event details: %v. Calling quit on socket: %s", event.Event, event.Data, executorSocket)
				if err := execStop(executorSocket); err != nil {
					logrus.Errorf("qmpEventHandler: Exception while stopping domain with socket: %s. %s", executorSocket, err.Error())
				}
				if err := execQuit(executorSocket); err != nil {
					logrus.Errorf("qmpEventHandler: Exception while quitting domain with socket: %s. %s", executorSocket, err.Error())
				}
			default:
				//Not handling the following events: RESUME, NIC_RX_FILTER_CHANGED, RTC_CHANGE, POWERDOWN, STOP
				logrus.Debugf("qmpEventHandler: Unhandled event: %s from listenerSocket: %s", event.Event, listenerSocket)
			}
		}
	}
}
