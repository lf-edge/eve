package main

import (
	"context"
	"fmt"
	"github.com/lf-edge/eve/pkg/pillar/agentlog"
	"github.com/lf-edge/eve/pkg/pillar/base"
	"github.com/lf-edge/eve/pkg/pillar/types"
	"github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

const (
	//PIDFile is the file to store the PID
	PIDFile = types.MemoryMonitorDir + "/psi-collector/psi-collector.pid"
)

var log *base.LogObject

func createPIDFile() error {
	f, err := os.Create(PIDFile)
	if err != nil {
		log.Errorf("Failed to create PID file: %v", err)
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%d", os.Getpid()))
	if err != nil {
		log.Errorf("Failed to write PID to file: %v", err)
		return err
	}
	return nil
}

func main() {
	logger := logrus.New()
	log = base.NewSourceLogObject(logger, "psi-collector", os.Getpid())
	// Check if the collector is already running
	if _, err := os.Stat(PIDFile); err == nil {
		log.Noticef("Memory PSI Collector is already running")
		return
	}
	// Create a PID file
	err := createPIDFile()
	if err != nil {
		log.Errorf("Failed to create PID file: %v", err)
		return
	}
	defer os.Remove(PIDFile)
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	go func() {
		<-signalChan
		os.Remove(PIDFile)
		os.Exit(0)
	}()
	log.Noticef("Starting Memory PSI Collector")
	err = agentlog.MemoryPSICollector(log, context.Background())
	if err != nil {
		fmt.Println("MemoryPSICollector failed: ", err)
	}
}
