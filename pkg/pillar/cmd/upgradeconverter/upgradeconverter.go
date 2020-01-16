package upgradeconverter

import (
	"flag"
	"log"
)

type ConverterAction uint8

const (
	Convert ConverterAction = iota + 1
	CleanupOld
	CleanupNew
	NoAction
)

var conversionHandlers []ConversionHandler

func Run() {

	actionStr := flag.String("actionStr", "", "Choose an action from convert/cleanupOld/cleanupNew")
	action := Convert
	if *actionStr == "convert" {
		action = Convert
	} else if *actionStr == "cleanupOld" {
		action = CleanupOld
	} else if *actionStr == "cleanupNew" {
		action = CleanupNew
	} else {
		action = NoAction
	}
	flag.Parse()

	conversionHandlers = []ConversionHandler {
		{
			description: "Convert Global Settings to new format",
			handlerFunc: handleUpgradeGlobalConfig,
		},
	}
	for _, handler := range conversionHandlers {
		log.Printf("Running Conversion handler: %s", handler.description)
		err := handler.handlerFunc(action)
		if err != nil {
			log.Fatalf("An error occured %s", err)
		}
	}
}

type HandlerFunc func(action ConverterAction) error

type ConversionHandler struct {
	description string
	handlerFunc HandlerFunc
}

