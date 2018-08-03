package sftp

import (
	"fmt"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"log"
	"strings"
)

const (
	SingleMB int64 = 1024 * 1024
)

// stats update
type UpdateStats struct {
	Size  int64 // complete size to upload/download
	Asize int64 // current size uploaded/downloaded
}

type NotifChan chan UpdateStats

func getSftpClient(host, user, pass string) (*sftp.Client, error) {
	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(
				func(user, instruction string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i, _ := range answers {
						answers[i] = pass
					}
					return answers, nil
				}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// We break this up into a DNS lookup and a Dial only to be able to detect
	// the errors better
	args := strings.Split(host, ":")
	if _, err := net.LookupHost(args[0]); err != nil {
		log.Printf("LookupHost error: %s", err)
		return nil, err
	}

	client, err := ssh.Dial("tcp", host, clientConfig)
	if err != nil {
		if strings.Contains(err.Error(), "ssh: unable to authenticate") {
			return nil, err
		}
		return nil, err
	}
	session, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}

	return session, nil
}

func ExecCmd(cmd, host, user, pass, remoteFile, localFile string, prgNotify NotifChan) (int64, error) {
	client, err := getSftpClient(host, user, pass)
	if err != nil {
		return 0, err
	}
	defer client.Close()
	switch cmd {
	case "ls":
		cnt := 0
		walker := client.Walk(remoteFile)
		for walker.Step() {
			if err := walker.Err(); err != nil {
				log.Printf("%v", err)
				continue
			}
			cnt += 1
		}
		return int64(cnt), nil
	case "fetch":
		fr, err := client.Open(remoteFile)
		if err != nil {
			return 0, err
		}
		fi, err := fr.Stat()
		if err != nil {
			return 0, err
		}
		defer fr.Close()

		fl, err := os.Create(localFile)
		if err != nil {
			return 0, err
		}
		defer fl.Close()

		chunkSize := SingleMB
		var written, copiedSize int64
		stats := UpdateStats{}
		stats.Size = fi.Size()
		for {
			if written, err = io.CopyN(fl, fr, chunkSize); err != nil && err != io.EOF {
				return 0, err
			}
			copiedSize += written
			if written != chunkSize {
				// Must have reached EOF
				err = nil
				break
			}
			stats.Asize = copiedSize
			if prgNotify != nil {
				select {
				case prgNotify <- stats:
				default: //ignore we cannot write
				}
			}
		}
		return copiedSize, err
	case "put":
		fr, err := client.Create(remoteFile)
		if err != nil {
			return 0, err
		}
		fi, err := fr.Stat()
		if err != nil {
			return 0, err
		}
		defer fr.Close()

		fl, err := os.Open(localFile)
		if err != nil {
			return 0, err
		}
		defer fl.Close()

		chunkSize := SingleMB
		var written, copiedSize int64
		stats := UpdateStats{}
		stats.Size = fi.Size()
		for {
			if written, err = io.CopyN(fr, fl, chunkSize); err != nil && err != io.EOF {
				return 0, err
			}
			copiedSize += written
			if written != chunkSize {
				// Must have reached EOF
				err = nil
				break
			}
			stats.Asize = copiedSize
			if prgNotify != nil {
				select {
				case prgNotify <- stats:
				default: //ignore we cannot write
				}
			}
		}
		return copiedSize, err
	case "stat":
		f, err := client.Open(remoteFile)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return 0, err
		}
		return fi.Size(), nil
	case "rm":
		if err := client.Remove(remoteFile); err != nil {
			log.Printf("unable to remove file: %v", err)
		}
		return 0, err
	default:
		return 0, fmt.Errorf("unknown subcommand: %v", cmd)
	}
}
