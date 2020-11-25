// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package zedUpload

import (
	"bytes"
	"fmt"
	"io"
)

const (
	//SingleMB represents data size of 1MB
	SingleMB int64 = 1024 * 1024
)

// ChunkData contains the details of Chunks being downloaded
type ChunkData struct {
	Size  int64  // complete size to upload/download
	Chunk []byte // chunk data being uploaded/downloaded
	EOF   bool   // denotes last chunk of the file
}

func processChunkByChunk(readCloser io.ReadCloser, size int64, chunkChan chan ChunkData) error {
	fmt.Println("processChunkByChunk started", size)
	var processed int64
	var eof bool
	for processed < size {
		var rbuf bytes.Buffer
		bufferSize := size - processed
		if bufferSize > SingleMB {
			bufferSize = SingleMB
		} else {
			eof = true
		}
		written, err := io.CopyN(&rbuf, readCloser, int64(bufferSize))
		if err != nil {
			return err
		}
		chunkChan <- ChunkData{Size: size, Chunk: rbuf.Bytes(), EOF: eof}
		processed += written
	}
	readCloser.Close()
	return nil
}
