// Copyright (c) 2021 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/pubsub"
	"github.com/lf-edge/eve/pkg/pillar/pubsub/socketdriver"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
)

var (
	runOnServer bool // container running inside remote linux host
	querytype   string
	cmdTimeout  string
	log         *base.LogObject
	trigPubchan chan bool
	rePattern   *regexp.Regexp
	evStatus    types.EdgeviewStatus
)

const (
	agentName       = "edgeview"
	closeMessage    = "+++Done+++"
	edgeViewVersion = "0.8.2"
	cpLogFileString = "copy-logfiles"
	clientIPMsg     = "YourEndPointIPAddr:"
)

type cmdOpt struct {
	Version      string `json:"version"`
	ClientEPAddr string `json:"clientEPAddr"`
	Network      string `json:"network"`
	System       string `json:"system"`
	Pubsub       string `json:"pubsub"`
	Logopt       string `json:"logopt"`
	Timerange    string `json:"timerange"`
	IsJSON       bool   `json:"isJSON"`
	Extraline    int    `json:"extraline"`
	Logtype      string `json:"logtype"`
}

func main() {
	pInst := flag.Int("inst", 0, "instance ID (1-5)")
	phelpopt := flag.Bool("help", false, "command-line help")
	phopt := flag.Bool("h", false, "command-line help")
	pServer := flag.Bool("server", false, "service edge-view queries")
	ptoken := flag.String("token", "", "session token")
	pDebug := flag.Bool("debug", false, "log more in debug")
	flag.Parse()

	logger := evLogger(*pDebug)

	if *pServer {
		runOnServer = true
	}

	initOpts()
	setupRegexp()

	if runOnServer {
		values := flag.Args()
		for _, cmd := range values {
			if cmd == "techsupport" {
				isTechSupport = true
				break
			}
		}
		if isTechSupport {
			cmds := cmdOpt{}
			runTechSupport(cmds, true)
		}
	}

	var wsAddr, pathStr string
	if *ptoken != "" {
		var err error
		wsAddr, pathStr, err = getAddrFromJWT(*ptoken, *pServer, *pInst)
		if err != nil {
			fmt.Printf("%v\n", err)
			if *phelpopt || *phopt {
				printHelp("")
			}
			return
		}
	} else {
		fmt.Printf("-token option is needed\n")
		return
	}

	var intSignal chan os.Signal
	var fstatus fileCopyStatus
	remotePorts := make(map[int]int)
	var tcpclientCnt int
	var pqueryopt, pnetopt, psysopt, ppubsubopt, logopt, timeopt string
	var jsonopt bool
	typeopt := "all"
	extraopt := 0
	values := flag.Args()
	var skiptype string
	// the reason for this loop to get our own params is that it allows
	// some options do not have to specify the "-something" in the front.
	// the flag does not allow this.
	// for example, put all the common usage in a script:
	// ./myscript.sh log/<pattern>
	// or ./myscript.sh log/<pattern> -time 0.2-0.5 -json
	// or ./myscript.sh -device <ip-addr> route
	for _, word := range values {
		if skiptype != "" {
			switch skiptype {
			case "time":
				timeopt = word
			case "type":
				typeopt = word
			case "line":
				numline, _ := strconv.Atoi(word)
				extraopt = numline
			case "token":
				*ptoken = word
			case "inst":
			default:
			}
			skiptype = ""
			continue
		}
		if strings.HasSuffix(word, "-help") || strings.HasSuffix(word, "-h") {
			*phelpopt = true
		} else if strings.HasSuffix(word, "-server") {
			*pServer = true
		} else if strings.HasSuffix(word, "-json") {
			jsonopt = true
		} else if strings.HasSuffix(word, "-debug") {
			*pDebug = true
		} else if strings.HasSuffix(word, "-time") {
			skiptype = "time"
		} else if strings.HasSuffix(word, "-type") {
			skiptype = "type"
		} else if strings.HasSuffix(word, "-line") {
			skiptype = "line"
		} else if strings.HasSuffix(word, "-token") {
			skiptype = "token"
		} else if strings.HasSuffix(word, "-inst") {
			skiptype = "inst"
		} else {
			pqueryopt = word
		}
	}

	if *phopt || *phelpopt {
		printHelp(pqueryopt)
		return
	}

	// query option syntax checks
	if pqueryopt != "" {
		if strings.HasPrefix(pqueryopt, "log/") {
			logs := strings.SplitN(pqueryopt, "log/", 2)
			if len(logs) != 2 {
				fmt.Printf("log/ needs search string\n")
				printHelp("")
				return
			}
			logopt = logs[1]
			if logopt == "" {
				fmt.Printf("log/ needs search string\n")
				printHelp("")
				return
			}
			if logopt == cpLogFileString {
				fstatus.cType = copyLogFiles
			}
		} else if strings.HasPrefix(pqueryopt, "pub/") {
			pubs := strings.SplitN(pqueryopt, "pub/", 2)
			if len(pubs) != 2 {
				fmt.Printf("pub/ option error\n")
				printHelp("")
				return
			}
			ppubsubopt = pubs[1]
			_, err := checkOpts(ppubsubopt, pubsubopts)
			if err != nil {
				fmt.Printf("pub/ option error\n")
				printHelp("")
				return
			}
		} else if strings.HasPrefix(pqueryopt, "app/") {
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "app") {
			psysopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "tcp/") {
			var ok bool
			ok, tcpclientCnt, remotePorts = processTCPcmd(pqueryopt, remotePorts)
			if !ok {
				return
			}
			pnetopt = pqueryopt
		} else if strings.HasPrefix(pqueryopt, "cp/") {
			psysopt = pqueryopt
			fstatus.cType = copySingleFile
		} else if strings.HasPrefix(pqueryopt, "tar/") {
			psysopt = pqueryopt
			fstatus.cType = copyTarFiles
		} else {
			_, err := checkOpts(pqueryopt, netopts)
			if err != nil {
				_, err = checkOpts(pqueryopt, sysopts)
				if err == nil {
					psysopt = pqueryopt
				}
			} else {
				pnetopt = pqueryopt
			}
			if err != nil {
				fmt.Printf("info: %s, not supported\n", pqueryopt)
				printHelp("")
				return
			}

			if psysopt == "techsupport" {
				fstatus.cType = copyTechSupport
			}
		}
	}

	if !runOnServer {
		// client side can break the session
		intSignal = make(chan os.Signal, 1)
		signal.Notify(intSignal, os.Interrupt)
	}
	urlWSS := url.URL{Scheme: "wss", Host: wsAddr, Path: pathStr}

	var done chan struct{}
	var tokenHash16 string
	hostname, _ := os.Hostname()
	if edgeviewInstID > 0 {
		hostname = hostname + "-inst-" + strconv.Itoa(edgeviewInstID)
	}
	tokenHash16 = string(getTokenHashString(*ptoken))
	fmt.Printf("%s connecting to %s\n", hostname, urlWSS.String())
	// on server, the script will retry in some minutes later
	ok := setupWebC(hostname, tokenHash16, urlWSS, runOnServer)
	if !ok {
		return
	}
	defer websocketConn.Close()
	done = make(chan struct{})

	queryCmds := cmdOpt{
		Version:   edgeViewVersion,
		Network:   pnetopt,
		System:    psysopt,
		Pubsub:    ppubsubopt,
		Logopt:    logopt,
		Timerange: timeopt,
		IsJSON:    jsonopt,
		Extraline: extraopt,
	}
	if typeopt != "all" {
		queryCmds.Logtype = typeopt
	}
	if logopt != "" && timeopt == "" { // default log search is previous half an hour
		queryCmds.Timerange = "0-0.5"
	}

	// for edgeview server side to use
	var infoPub pubsub.Publication
	trigPubchan = make(chan bool, 1)
	pubStatusTimer := time.NewTimer(1 * time.Second)
	pubStatusTimer.Stop()

	// edgeview container can run in 2 different modes:
	// 1) websocket server mode, runs on device: 'runOnServer' is set
	// 2) websocket client mode, runs on operator/laptop side
	if runOnServer { // 1) websocket mode on device 'server' side

		err := initPolicy()
		if err != nil {
			log.Noticef("edgeview exit, init policy err. %v", err)
			return
		}

		infoPub = initpubInfo(logger)
		if infoPub == nil && edgeviewInstID <= 1 {
			log.Noticef("edgeview exit, initpub, instid %d", edgeviewInstID)
			return
		}

		// send keepalive to prevent nginx reverse-proxy timeout
		go sendKeepalive()

		go func() {
			defer close(done)
			// publish stats when it starts, to let controller know edgeview is active on device
			if edgeviewInstID <= 1 {
				trigPubchan <- true
			}
			for {
				mtype, msg, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, tokenHash16, urlWSS, err) {
						continue
					}
					log.Noticef("edgeview exit, websocket err %v", err)
					return
				}

				var recvCmds cmdOpt
				isJSON, verifyOK, message := verifyEnvelopeData(msg)
				if !isJSON {
					if strings.Contains(string(msg), "no device online") {
						log.Tracef("read: peer not there yet, continue")
					} else {
						ok := checkClientIPMsg(string(msg))
						if ok {
							log.Tracef("My endpoint IP: %s\n", basics.evendpoint)
						}
					}
					continue
				}
				if !verifyOK {
					log.Noticef("authen failed on json msg")
					continue
				}

				if mtype == websocket.TextMessage {
					if strings.Contains(string(message), "no device online") ||
						strings.Contains(string(message), closeMessage) {
						log.Tracef("read: no device, continue")
						continue
					} else {
						if isTCPServer {
							close(tcpServerDone)
							continue
						}
					}

					err := json.Unmarshal(message, &recvCmds)
					if err != nil {
						log.Noticef("unmarshal json msg error: %v", err)
						continue
					} else {
						// check the query commands against defined policy
						ok, errmsg := checkCmdPolicy(recvCmds, &evStatus)
						if !ok {
							_ = addEnvelopeAndWriteWss([]byte("cmd policy check failed: "+errmsg), true)
							sendCloseToWss()
							continue
						}
						trigPubchan <- true
					}
				}
				if isSvrCopy {
					copyMsgChn <- message
				} else if isTCPServer {
					recvClientData(mtype, message)
				} else {
					// process client query
					go goRunQuery(recvCmds)
				}
			}
		}()
	} else { // 2) websocket mode on client side

		// send keepalive to prevent nginx reverse-proxy timeout
		go sendKeepalive()

		// get the client ip address
		mtype, msg, err := websocketConn.ReadMessage()
		if err == nil && mtype == websocket.TextMessage {
			ok := checkClientIPMsg(string(msg))
			if ok {
				var instStr string
				if edgeviewInstID > 1 {
					instStr = fmt.Sprintf("-inst-%d", edgeviewInstID)
				}
				fmt.Printf("Client%s endpoint IP: %s\n", instStr, basics.evendpoint)
				queryCmds.ClientEPAddr = basics.evendpoint
			}
		}
		if !clientSendQuery(queryCmds) {
			return
		}
		go func() {
			defer close(done)
			for {
				mtype, msg, err := websocketConn.ReadMessage()
				if err != nil {
					if retryWebSocket(hostname, tokenHash16, urlWSS, err) {
						continue
					}
					return
				}

				isJSON, verifyOK, message := verifyEnvelopeData(msg)
				if !isJSON {
					fmt.Printf("%s\nreceive message done\n", string(msg))
					done <- struct{}{}
					break
				}

				if !verifyOK {
					fmt.Printf("\nverify msg failed\n")
					done <- struct{}{}
					break
				}

				if strings.Contains(string(message), closeMessage) {
					done <- struct{}{}
					break
				} else if fstatus.cType != unknownCopy {
					recvCopyFile(message, &fstatus, mtype)
					if mtype == websocket.TextMessage && fstatus.cType != unknownCopy && fstatus.f != nil {
						defer fstatus.f.Close()
					}
				} else if isTCPClient {
					if mtype == websocket.TextMessage {
						if !tcpClientRun { // got ok message from tcp server side, run client
							if bytes.Contains(message, []byte(tcpSetupOKMessage)) {
								tcpClientsLaunch(tcpclientCnt, remotePorts)
							} else {
								// this could be the tcp policy disallow the setup message
								fmt.Printf("%s\n", message)
							}
						} else {
							fmt.Printf(" tcp client running, receiving close probably due to server timed out: %v\n", string(message))
							done <- struct{}{}
							break
						}
					} else {
						recvServerData(mtype, message)
					}
				} else {
					fmt.Printf("%s", message)
				}
			}
		}()
	}

	if runOnServer && edgeviewInstID == 1 {
		go serverEvStats()
	}

	var waitPulish bool
	// ssh or non-ssh client wait for replies and finishes with a 'done' or gets a Ctrl-C
	// non-ssh server will be killed when the session is expired with the script
	for {
		select {
		case <-trigPubchan:
			// not to publish the status too fast
			if !waitPulish {
				pubStatusTimer = time.NewTimer(15 * time.Second)
				waitPulish = true
			}
		case <-pubStatusTimer.C:
			waitPulish = false
			doInfoPub(infoPub)
		case <-done:
			tcpClientSendDone()
			return
		case <-intSignal:
			tcpClientSendDone()
			return
		}
	}
}

func goRunQuery(cmds cmdOpt) {
	var err error
	wsMsgCount = 0
	wsSentBytes = 0
	// save output to buffer
	readP, writeP, err = openPipe()
	if err == nil {
		parserAndRun(cmds)
		if isTCPServer {
			return
		}
		closePipe(false)
		sendCloseToWss()
		log.Tracef("Sent %d messages, total %d bytes to websocket", wsMsgCount, wsSentBytes)
	}
}

func parserAndRun(cmds cmdOpt) {
	cmdTimeout = cmds.Timerange
	querytype = cmds.Logtype

	getBasics()
	//
	// All query commands are categorized into one of the 'network', 'system', 'pubssub' and 'log-search'
	// This is shared by ssh and non-ssh mode.
	//
	if cmds.Network != "" {
		runNetwork(cmds.Network)
	} else if cmds.Pubsub != "" {
		runPubsub(cmds.Pubsub)
	} else if cmds.System != "" {
		runSystem(cmds, cmds.System)
	} else if cmds.Logopt != "" {
		runLogSearch(cmds)
	} else {
		log.Noticef("no supported options")
		return
	}
}

func initpubInfo(logger *logrus.Logger) pubsub.Publication {
	if edgeviewInstID > 1 {
		return nil
	}
	ps := *pubsub.New(&socketdriver.SocketDriver{Logger: logger, Log: log}, logger, log)
	infoPub, err := ps.NewPublication(
		pubsub.PublicationOptions{
			AgentName: agentName,
			TopicType: types.EdgeviewStatus{},
		})
	if err != nil {
		log.Errorf("evinfopub: pubsub create error: %v", err)
		return nil
	}
	err = infoPub.ClearRestarted()
	if err != nil {
		log.Errorf("evinfopub: pubsub clear restart error: %v", err)
		return nil
	}

	return infoPub
}

func sendKeepalive() {
	ticker := time.NewTicker(90 * time.Second)
	for {
		for range ticker.C {
			wssWrMutex.Lock()
			if websocketConn != nil {
				err := websocketConn.WriteMessage(websocket.PingMessage, []byte("keepalive"))
				if err != nil {
					log.Errorf("write ping err: %v", err)
				}
			}
			wssWrMutex.Unlock()
		}
	}
}

// check for user provided strings in command param
func setupRegexp() {
	// allow letters, numbers,
	// '/' for path, '.' for ip address, '@' for domain name, ':' for port; '-', '_' for filename
	// '=' for flow match, '+' for " +0x" pattern, ',' for pub/
	rePattern = regexp.MustCompile(`^[A-Za-z0-9 =\-_.:,/@]*$`)
}
