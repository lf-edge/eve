// Copyright (c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sync/errgroup"
)

type multiFileWriter struct {
	files   []*os.File
	pipeFds [2]int
	eg      errgroup.Group
}

func (w *multiFileWriter) run() {
	w.eg.Go(func() error {
		defer w.close()
		for {
			buf := make([]byte, 1024)
			n, err := syscall.Read(w.pipeFds[0], buf)
			if err != nil {
				return err
			}
			if n <= 0 {
				return nil
			}
			for _, f := range w.files {
				str := fmt.Sprintf("(%s) %s", f.Name(), buf[:n])
				f.Write([]byte(str))
			}
		}
	})
}

func (w *multiFileWriter) close() {
	for _, f := range w.files {
		f.Close()
	}
}

func (w *multiFileWriter) err() error {
	return w.eg.Wait()
}

func newMultiFileWriter(files []*os.File) (*multiFileWriter, *os.File) {
	w := &multiFileWriter{}

	w.files = files

	syscall.Pipe(w.pipeFds[:])
	f := os.NewFile(uintptr(w.pipeFds[1]), "pipe")

	w.run()

	return w, f
}
