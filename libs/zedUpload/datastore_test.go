package zedUpload_test

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
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

type unstableProxyCtx struct {
	limited       bool
	limit         bool
	startFromByte uint64
	delay         time.Duration
	dropPercent   int
	laddr, raddr  *net.TCPAddr
}

type unstableProxy struct {
	receivedBytes, sentBytes, discardBytes uint64
	lconn, rconn                           io.ReadWriteCloser
	wg                                     sync.WaitGroup
	ctx                                    *unstableProxyCtx
}

//newUnstableProxyStart creates proxy on :lport to connect to addr:rport with dropPercent of bytes
//during delay time after startFromByte bytes received
func newUnstableProxyStart(lport, rport int, addr string, startFromByte uint64, delay time.Duration, dropPercent int) error {
	rand.Seed(time.Now().Unix())
	laddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf(":%d", lport))
	if err != nil {
		return fmt.Errorf("failed to resolve local address: %s", err)
	}
	raddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", addr, rport))
	if err != nil {
		return fmt.Errorf("failed to resolve remote address: %s", err)
	}
	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		return fmt.Errorf("failed to open local port to listen: %s", err)
	}
	uProxy := &unstableProxyCtx{
		laddr:         laddr,
		raddr:         raddr,
		startFromByte: startFromByte,
		delay:         delay,
		dropPercent:   dropPercent,
	}

	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				fmt.Printf("Failed to accept connection '%s'", err)
				continue
			}

			p := uProxy.newUnstableProxy(conn)

			go p.start()
		}
	}()
	return nil
}

func (ctx *unstableProxyCtx) newUnstableProxy(lconn *net.TCPConn) *unstableProxy {
	return &unstableProxy{
		lconn: lconn,
		ctx:   ctx,
	}
}

func (p *unstableProxy) start() {
	defer p.lconn.Close()

	var err error

	p.rconn, err = net.DialTCP("tcp", nil, p.ctx.raddr)
	if err != nil {
		fmt.Printf("Remote connection failed: %s\n", err)
		return
	}
	defer p.rconn.Close()

	fmt.Printf("Opened %s >>> %s\n", p.ctx.laddr.String(), p.ctx.raddr.String())

	p.wg.Add(2)

	go p.pipe(p.lconn, p.rconn)
	go p.pipe(p.rconn, p.lconn)

	p.wg.Wait()

	fmt.Printf("Closed (%d bytes sent, %d bytes received, %d bytes discard)\n", p.sentBytes, p.receivedBytes, p.discardBytes)
}

func (p *unstableProxy) pipe(src, dst io.ReadWriteCloser) {
	defer p.wg.Done()
	isSend := src == p.lconn

	bufLen := 1024
	buff := make([]byte, bufLen)
	deferClose := false
	for deferClose == false {
		if !isSend {
			if p.receivedBytes+uint64(bufLen) > p.ctx.startFromByte && !p.ctx.limited {
				if !p.ctx.limited && !p.ctx.limit {
					fmt.Println("Limit started at: ", time.Now().String())
					p.ctx.limit = true
					time.AfterFunc(p.ctx.delay, func() {
						fmt.Println("Limit ended at: ", time.Now().String())
						p.ctx.limited = true
						p.ctx.limit = false
					})
				}
			}
		}
		n, err := src.Read(buff)
		if err != nil && err != io.EOF {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				fmt.Printf("Read failed '%s'\n", err)
			}
			return
		}
		if err == io.EOF {
			deferClose = true
		}

		discard := p.ctx.limit && rand.Intn(100) < p.ctx.dropPercent

		if !discard {
			n, err = dst.Write(buff[:n])
		}

		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				fmt.Printf("Write failed '%s'\n", err)
			}
			return
		}
		if isSend {
			p.sentBytes += uint64(n)
		} else {
			if discard {
				p.discardBytes += uint64(n)
			} else {
				p.receivedBytes += uint64(n)
			}
		}
	}
	_ = src.Close()
	_ = dst.Close()
}
