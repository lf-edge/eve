// Copyright(c) 2017-2018 Zededa, Inc.
// All rights reserved.

package sftp

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/lf-edge/eve-libs/zedUpload/types"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	SingleMB int64 = 1024 * 1024
)

// Resp response data from executing commands
type Resp struct {
	List          []string //list of images at given path
	ContentLength int64
	Stats         types.UpdateStats
}

func getSftpClient(host, user, pass string) (*sftp.Client, error) {
	clientConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
			ssh.KeyboardInteractive(
				func(user, instruction string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i := range answers {
						answers[i] = pass
					}
					return answers, nil
				}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(10) * time.Second,
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
		return nil, err
	}
	session, err := sftp.NewClient(client)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func ExecCmd(cmd, host, user, pass, remoteFile, localFile string,
	objSize int64, prgNotify types.StatsNotifChan) (types.UpdateStats, Resp) {

	var list []string
	stats := types.UpdateStats{}
	client, err := getSftpClient(host, user, pass)
	if err != nil {
		stats.Error = fmt.Errorf("sftpclient failed for %s: %s", host, err)
		return stats, Resp{}
	}
	defer client.Close()
	switch cmd {
	case "ls":
		walker := client.Walk(remoteFile)
		for walker.Step() {
			if err := walker.Err(); err != nil {
				stats.Error = err
				return stats, Resp{}
			}
			file := strings.Replace(walker.Path(), remoteFile+"/", "", -1)
			list = append(list, file)
		}
		types.SendStats(prgNotify, stats)
		return stats, Resp{List: list}
	case "fetch":
		fr, err := client.Open(remoteFile)
		if err != nil {
			stats.Error = fmt.Errorf("open failed for %s: %s",
				remoteFile, err)
			return stats, Resp{}
		}
		tempLocalFile := localFile
		index := strings.LastIndex(tempLocalFile, "/")
		dir_err := os.MkdirAll(tempLocalFile[:index+1], 0755)
		if dir_err != nil {
			stats.Error = dir_err
			return stats, Resp{}
		}

		fl, err := os.Create(localFile)
		if err != nil {
			stats.Error = err
			return stats, Resp{}
		}
		defer fl.Close()

		chunkSize := SingleMB
		var written, copiedSize int64
		stats.Size = objSize
		for {
			if written, err = io.CopyN(fl, fr, chunkSize); err != nil && err != io.EOF {
				stats.Error = err
				return stats, Resp{}
			}
			copiedSize += written
			if written != chunkSize {
				// Must have reached EOF
				break
			}
			stats.Asize = copiedSize
			types.SendStats(prgNotify, stats)
		}
		return stats, Resp{}
	case "put":
		tempRemoteFile := remoteFile
		index := strings.LastIndex(tempRemoteFile, "/")
		err := client.MkdirAll(tempRemoteFile[:index+1])
		if err != nil {
			stats.Error = fmt.Errorf("mkdir failed for %s: %s",
				tempRemoteFile[:index+1], err)
			return stats, Resp{}
		}
		fr, err := client.Create(remoteFile)
		if err != nil {
			stats.Error = fmt.Errorf("create failed for %s: %s",
				remoteFile, err)
			return stats, Resp{}
		}
		defer fr.Close()

		fl, err := os.Open(localFile)
		if err != nil {
			stats.Error = err
			return stats, Resp{}
		}
		fSize, err := fl.Stat()
		if err != nil {
			stats.Error = err
			return stats, Resp{}
		}
		defer fl.Close()

		chunkSize := SingleMB
		var written, copiedSize int64
		stats := types.UpdateStats{}
		stats.Size = fSize.Size()
		for {
			if written, err = io.CopyN(fr, fl, chunkSize); err != nil && err != io.EOF {
				stats.Error = err
				return stats, Resp{}
			}
			copiedSize += written
			if written != chunkSize {
				// Must have reached EOF
				return stats, Resp{}
			}
			stats.Asize = copiedSize
			types.SendStats(prgNotify, stats)
		}
		// control never gets here - we will return from inside the loop.
	case "stat":
		file, err := client.Lstat(remoteFile)
		if err != nil {
			stats.Error = fmt.Errorf("lstat failed for %s: %s",
				remoteFile, err)
			stats.Error = err
			return stats, Resp{}
		}
		return stats, Resp{ContentLength: file.Size()}
	case "rm":
		err := client.Remove(remoteFile)
		if err != nil {
			stats.Error = fmt.Errorf("remove failed for %s: %s",
				remoteFile, err)
		}
		return stats, Resp{}
	default:
		stats.Error = fmt.Errorf("unknown subcommand: %v", cmd)
		return stats, Resp{}
	}
}
