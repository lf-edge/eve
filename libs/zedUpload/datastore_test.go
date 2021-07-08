package zedUpload_test

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"time"
)

const (
	// global parameters
	uploadDir       = "./test/input/"
	uploadFile      = "./test/input/zedupload_test.img"
	uploadFileSmall = "./test/input/zedupload_test_small.img"
)

func ensureFile(filename string, size int64) error {
	if info, err := os.Stat(filename); err != nil || info.Size() != size {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		p := make([]byte, size)
		if _, err := r.Read(p); err != nil {
			return err
		}
		if err := ioutil.WriteFile(filename, p, 0644); err != nil {
			return err
		}
	}
	return nil
}

func setup() error {
	// make sure that our upload files exist
	if err := os.MkdirAll(uploadDir, 0755); err != nil {
		return err
	}
	if err := ensureFile(uploadFile, 1024*1024); err != nil {
		return fmt.Errorf("error creating upload file %s: %v", uploadFile, err)
	}
	if err := ensureFile(uploadFileSmall, 1024); err != nil {
		return fmt.Errorf("error creating small upload file %s: %v", uploadFileSmall, err)
	}
	return nil
}

func hashFileMd5(filePath string) (string, error) {
	//Initialize variable returnMD5String now in case an error has to be returned
	var returnMD5String string

	//Open the passed argument and check for any error
	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	//Tell the program to call the following function when the current function returns
	defer file.Close()

	//Open a new hash interface to write to
	hash := md5.New()

	//Copy the file in the hash interface and check for any error
	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	//Get the 16 bytes hash
	hashInBytes := hash.Sum(nil)[:16]

	//Convert the bytes to a string
	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

func calculateMd5(filename string, chunkSize int64) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	dataSize, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return "", err
	}

	var (
		sumOfSums []byte
		parts     int
	)
	for i := int64(0); i < dataSize; i += chunkSize {
		length := chunkSize
		if i+chunkSize > dataSize {
			length = dataSize - i
		}
		sum, err := md5sum(f, i, length)
		if err != nil {
			return "", err
		}
		sumOfSums = append(sumOfSums, sum...)
		parts++
	}

	var finalSum []byte

	if parts == 1 {
		finalSum = sumOfSums
	} else {
		h := md5.New()
		_, err := h.Write(sumOfSums)
		if err != nil {
			return "", err
		}
		finalSum = h.Sum(nil)
	}
	sumHex := hex.EncodeToString(finalSum)

	if parts > 1 {
		sumHex += "-" + strconv.Itoa(parts)
	}

	return sumHex, nil
}

func md5sum(r io.ReadSeeker, start, length int64) ([]byte, error) {
	_, _ = r.Seek(start, io.SeekStart)
	h := md5.New()
	if _, err := io.CopyN(h, r, length); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}
