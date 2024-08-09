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

type ueventListener struct {
	isCancelled  atomic.Bool
	ueventReader io.ReadCloser
	usbdevices   map[string]*usbdevice
	uc           *usbmanagerController
}

func (uc *usbmanagerController) listenUSBPorts() {
	ul := ueventListener{
		usbdevices: map[string]*usbdevice{},
		uc:         uc,
	}
	ul.isCancelled.Store(false)
	uc.listenUSBStopChan = make(chan struct{})

	go ul.handleStop()

	go func() {
		retry := true
		for retry {
			retry = ul.readEvents()
		}
	}()
}

func (ul *ueventListener) handleStop() {
	// cancelling uevent reader
	<-ul.uc.listenUSBStopChan
	ul.isCancelled.Store(true)
	if ul.ueventReader != nil {
		ul.ueventReader.Close()
	}
}

func (ul *ueventListener) readEvents() bool {
	var err error
	ul.ueventReader, err = uevent.NewReader()
	if err != nil {
		log.Warnf("Opening uevent reader failed: %v - retrying", err)
		return true
	}

	ul.scanExistingUSBDevices()

	defer ul.ueventReader.Close()

	dec := uevent.NewDecoder(ul.ueventReader)

	for {
		evt, err := dec.Decode()
		if errors.Is(err, io.EOF) && ul.isCancelled.Load() {
			break
		} else if err != nil {
			log.Warnf("decoding uevent failed: %+v - retrying", err)
			return true
		}

		ueventFilePath := filepath.Join(sysFSPath, evt.Devpath, "uevent")
		ud := ueventFile2usbDevice(ueventFilePath)
		if ud == nil {
			ud = ul.usbdevices[ueventFilePath]
		}

		if ud == nil {
			continue
		}

		// bind, not add: https://github.com/olavmrk/usb-libvirt-hotplug/issues/4
		if evt.Action == "bind" {
			_, ok := ul.usbdevices[ud.ueventFilePath]
			if ok {
				continue
			}

			ul.usbdevices[ud.ueventFilePath] = ud
			ul.uc.addUSBDevice(*ud)
		} else if evt.Action == "remove" {
			ud, ok := ul.usbdevices[ueventFilePath]
			if ok {
				ul.uc.removeUSBDevice(*ud)
				delete(ul.usbdevices, ueventFilePath)
			}
		}
	}
	return false
}

func (ul *ueventListener) scanExistingUSBDevices() {
	newUsbdevices := make(map[string]*usbdevice)
	for _, ud := range walkUSBPorts() {
		newUsbdevices[ud.ueventFilePath] = ud
	}
	log.Tracef("previous usbdevices: %+v | new usbdevices: %+v", ul.usbdevices, newUsbdevices)
	for ueventFilePath, ud := range newUsbdevices {
		_, found := ul.usbdevices[ueventFilePath]
		if !found {
			log.Tracef("usb device from walking: %+v", ud)
			ul.uc.addUSBDevice(*ud)
		}
	}
	for ueventFilePath, ud := range ul.usbdevices {
		_, found := newUsbdevices[ueventFilePath]
		if !found {
			log.Tracef("remove usb device from walking: %+v", ud)
			ul.uc.removeUSBDevice(*ud)
		}
	}

	ul.usbdevices = newUsbdevices
}
