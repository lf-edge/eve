package main

import (
	"flag"
	"fmt"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
	"github.com/zededa/go-provision/types"
)

const (
	ledStatusDirName = "/var/run/ledmanager/status/"
)

var count uint64
var oldBlinkCount uint64

// Set from Makefile
var Version = "No version specified"

func main() {

	log.SetOutput(os.Stdout)
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	versionPtr := flag.Bool("v", false, "Version")
	flag.Parse()
	if *versionPtr {
		fmt.Printf("%s: %s\n", os.Args[0], Version)
		return
	}
	log.Printf("Starting ledmanager\n")

	ledChanges := make(chan string)
	var w Watcher
	go w.LedWatcher(ledStatusDirName, ledChanges)
	log.Println("called watcher...")
	for {
		select {
		case change := <-ledChanges:
			{
				log.Println("change: ", change)
				HandleLedBlink(change)
				continue
			}
		}
	}
}
func HandleLedBlink(change string) {

	ledStatusFileName := ledStatusDirName + "/ledstatus.json"
	testFile := "/var/run/ledmanager/blink.json"

	operation := string(change[0])
	fileName := string(change[2:])

	if !strings.HasSuffix(fileName, ".json") {
		log.Printf("Ignoring file <%s> operation %s\n",
			fileName, operation)
		return
	}
	if operation == "D" {
		err := os.Remove(ledStatusFileName)

		if err != nil {
			log.Println(err)
			return
		}
	}

	if operation != "M" {
		log.Fatal("Unknown operation from Watcher: ",
			operation)
	}

	log.Println("value of count: ", count)
	if count > 0 {
		log.Println("value of count: ", count)
		time.Sleep(time.Second * 1)
	}

	var countBlink = types.LedBlinkCounter{}
	cb, err := ioutil.ReadFile(ledStatusFileName)
	if err != nil {
		log.Printf("%s for %s\n", err, ledStatusFileName)
	}
	if err := json.Unmarshal(cb, &countBlink); err != nil {
		log.Printf("%s %T file: %s\n",
			err, countBlink, ledStatusFileName)
	}
	blinkCount := countBlink.BlinkCounter

	if oldBlinkCount == uint64(blinkCount) {
		log.Println("same event: ", blinkCount, oldBlinkCount)
		return
	}
	log.Println("blinkCount: ", blinkCount)
	//This is just a dummy code
	//we need to add the code
	//that will trigger the actual
	//LED blink on devices...

	//for now we are just writing
	//the blinkCounter in a file...
	b, err := json.Marshal(countBlink)
	if err != nil {
		log.Fatal(err, "json Marshal ledwatcher")
	}
	err = ioutil.WriteFile(testFile, b, 0644)
	if err != nil {
		log.Fatal("err: ", err, testFile)
	}
	oldBlinkCount = uint64(countBlink.BlinkCounter)
	count++
}
