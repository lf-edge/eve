// This file is drived from the code available in linuxkit project under Apache License v2
//    https://github.com/linuxkit/linuxkit/blob/master/pkg/init/cmd/service/logging.go

package containerd

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/containerd/containerd/cio"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	fifoDir        string = "/var/run/tasks/fifos"
	logDumpCommand byte   = iota
)

type logio struct {
	config cio.Config
}

func (c *logio) Config() cio.Config {
	return c.config
}

func (c *logio) Cancel() {
}

func (c *logio) Wait() {
}

func (c *logio) Close() error {
	return nil
}

// Log provides access to a log by path or io.WriteCloser
type Log interface {
	Path(string) string                  // Path of the log file (may be a FIFO)
	Open(string) (io.WriteCloser, error) // Opens a log stream
	Dump(string)                         // Copies logs to the console
}

// GetLog returns the log destination we should use.
func GetLog() Log {
	if _, err := os.Stat(logWriteSocket); !os.IsNotExist(err) {
		_ = os.MkdirAll(fifoDir, 0777)
		return &remoteLog{
			fifoDir: fifoDir,
		}
	}
	return &nullLog{}
}

type nullWriterCloser struct {
	io.Writer
}

func (n nullWriterCloser) Close() error {
	return nil
}

type nullLog struct {
}

// Path returns the name of a log file path for the named service.
func (f *nullLog) Path(n string) string {
	return "/dev/null"
}

// Open a log file for the named service.
func (f *nullLog) Open(n string) (io.WriteCloser, error) {
	return nullWriterCloser{ioutil.Discard}, nil
}

// Dump copies logs to the console.
func (f *nullLog) Dump(n string) {
}

type remoteLog struct {
	fifoDir string
}

// Path returns the name of a FIFO connected to the logging daemon.
func (r *remoteLog) Path(n string) string {
	path := filepath.Join(r.fifoDir, n+".log")
	if err := syscall.Mkfifo(path, 0600); err != nil {
		return "/dev/null"
	}
	go func() {
		// In a goroutine because Open of the FIFO will block until
		// containerd opens it when the task is started.
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err != nil {
			// Should never happen: we just created the fifo
			log.Printf("failed to open fifo %s: %s", path, err)
		}
		defer syscall.Close(fd)
		if err := sendToLogger(n, fd); err != nil {
			// Should never happen: logging is enabled
			log.Printf("failed to send fifo %s to logger: %s", path, err)
		}
	}()
	return path
}

// Open a log file for the named service.
func (r *remoteLog) Open(n string) (io.WriteCloser, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		log.Fatal("Unable to create socketpair: ", err)
	}
	logFile := os.NewFile(uintptr(fds[0]), "")

	if err := sendToLogger(n, fds[1]); err != nil {
		return nil, err
	}
	return logFile, nil
}

// Dump copies logs to the console.
func (r *remoteLog) Dump(n string) {
	addr := net.UnixAddr{
		Name: logReadSocket,
		Net:  "unix",
	}
	conn, err := net.DialUnix("unix", nil, &addr)
	if err != nil {
		log.Printf("Failed to connect to logger: %s", err)
		return
	}
	defer conn.Close()
	nWritten, err := conn.Write([]byte{logDumpCommand})
	if err != nil || nWritten < 1 {
		log.Printf("Failed to request logs from logger: %s", err)
		return
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Printf("Failed to read log message: %s", err)
			return
		}
		// a line is of the form
		// <timestamp>,<log>;<body>
		prefixBody := strings.SplitN(line, ";", 2)
		csv := strings.Split(prefixBody[0], ",")
		if len(csv) < 2 {
			log.Printf("Failed to parse log message: %s", line)
			continue
		}
		if csv[1] == n {
			fmt.Print(line)
		}
	}
}

func sendToLogger(name string, fd int) error {
	var ctlSocket int
	var err error
	if ctlSocket, err = syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0); err != nil {
		return err
	}

	var ctlConn net.Conn
	if ctlConn, err = net.FileConn(os.NewFile(uintptr(ctlSocket), "")); err != nil {
		return err
	}
	defer ctlConn.Close()

	ctlUnixConn, ok := ctlConn.(*net.UnixConn)
	if !ok {
		// should never happen
		log.Fatal("Internal error, invalid cast.")
	}

	raddr := net.UnixAddr{Name: logWriteSocket, Net: "unixgram"}
	oobs := syscall.UnixRights(fd)
	_, _, err = ctlUnixConn.WriteMsgUnix([]byte(name), oobs, &raddr)
	if err != nil {
		return errors.New("logging system not enabled")
	}
	return nil
}
