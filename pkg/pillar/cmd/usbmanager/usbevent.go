// Copyright (c) 2023 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0
package usbmanager

import (
	"errors"
	"io"
	"path/filepath"
	"sync/atomic"

	"github.com/eshard/uevent"
)

func (uc *usbmanagerController) listenUSBPorts() {
	var isCancelled atomic.Bool

	usbdevices := make(map[string]*usbdevice)
	isCancelled.Store(false)

	r, err := uevent.NewReader()
	if err != nil {
		log.Fatal(err)
	}

	// goroutine for cancelling uevent reader
	uc.listenUSBStopChan = make(chan struct{})
	go func() {
		<-uc.listenUSBStopChan
		isCancelled.Store(true)
		r.Close()
		return
	}()

	go func() {
		for _, ud := range walkUSBPorts() {
			usbdevices[ud.ueventFilePath] = ud
			log.Tracef("usb device from walking: %+v", ud)
			uc.addUSBDevice(*ud)
		}

		defer r.Close()

		dec := uevent.NewDecoder(r)

		for {
			evt, err := dec.Decode()
			if errors.Is(err, io.EOF) && isCancelled.Load() {
				return
			} else if err != nil {
				log.Fatal(err)
			}

			ueventFilePath := filepath.Join(sysFSPath, evt.Devpath, "uevent")
			ud := ueventFile2usbDevice(ueventFilePath)
			if ud == nil {
				ud = usbdevices[ueventFilePath]
			}

			if ud == nil {
				continue
			}

			if evt.Action == "bind" {
				// bind, not add: https://github.com/olavmrk/usb-libvirt-hotplug/issues/4
				_, ok := usbdevices[ud.ueventFilePath]
				if ok {
					continue
				}

				usbdevices[ud.ueventFilePath] = ud
				uc.addUSBDevice(*ud)
			} else if evt.Action == "remove" {
				ud, ok := usbdevices[ueventFilePath]
				if ok {
					uc.removeUSBDevice(*ud)
					delete(usbdevices, ueventFilePath)
				}
			}
		}
	}()

}
