package main

import (
	"fmt"
	"log"
//	"os/exec"
	"protometrics"
//	"regexp"
//	"strconv"
//	"strings"
//	"io/ioutil"
	"github.com/golang/protobuf/proto"
//	"time"
	"net/http"
	"bytes"
)


func MakeInfoProtoBuf() {

	var ReportInfo = &protometrics.ZInfoMsg{}
	var cpu_count = 2
	var memory_size = 200
	var storage_size = 1000

	appType := new(protometrics.ZInfoTypes)
    *appType = protometrics.ZInfoTypes_ZiApp
    ReportInfo.Ztype = appType
	ReportInfo.DevId = proto.String("38455FA5-4132-4095-9AEF-F0A3CA242FA3")

	ReportAppInfo := new(protometrics.ZInfoApp)
    ReportAppInfo.AppID   = proto.String("38455FA5-4132-4095-9AEF-F0A3CA242FA3")
    ReportAppInfo.Ncpu    = proto.Uint32(uint32(cpu_count))
    ReportAppInfo.Memory  = proto.Uint32(uint32(memory_size))
    ReportAppInfo.Storage = proto.Uint32(uint32(storage_size))

	ReportVerInfo := new(protometrics.ZInfoSW)
    ReportVerInfo.SwVersion = proto.String("0.0.0.1")
    ReportVerInfo.SwHash = proto.String("0.0.0.1")

    ReportAppInfo.SwVersion = ReportVerInfo
	ReportInfo.Ainfo = ReportAppInfo

	fmt.Println(ReportInfo)
	fmt.Println(" ")

	data, err := proto.Marshal(ReportInfo)
	if err != nil {
		fmt.Println("marshaling error: ", err)
	}
	_, err = http.Post(statusURL, "application/x-proto-binary",
		bytes.NewBuffer(data))
	if err != nil {
		fmt.Println(err)
	}

	newTest := &protometrics.ZInfoMsg{}
	err = proto.Unmarshal(data, newTest)
	if err != nil {
		log.Fatal("unmarshaling error: ", err)
	}

	log.Println(newTest)
}
