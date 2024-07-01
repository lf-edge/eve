// Copyright(c) 2024 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"flag"
	"io/ioutil"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Cooling profile struct
type coolingMode struct {
	name   string  // Profile name
	points [][]int // Mapping points (Temp,PWM)
}

// FAN controlling struct
type fanCTRL struct {
	devPWM        string      // PWM device
	devThermal    string      // Thermal device
	cmode         coolingMode // Cooling profile
	checkInterval int         // Pooling interval (in seconds)
}

// Device interface
type deviceProfiles interface {
	Model() string                // Device model
	getQuietProfile() coolingMode // Quiet profile
	getCoolProfile() coolingMode  // Cool profile
}

type profileOrin struct {
}
type profileXavier struct {
}

// Thermal zone path to read temperature
const thermalDevice = string("/sys/devices/virtual/thermal/thermal_zone%d/temp")
// PWM fan device path
const fanSysDir = string("/sys/devices/platform/pwm-fan/hwmon/")
// Asset TAG sysfs path
const assetTagSysFs = string("/sys/class/dmi/id/chassis_asset_tag")
// Maximum PWM value
const maxPWM = 255

// Jetson Xavier device model
func (p profileXavier) Model() string {
	return "Jetson Xavier"
}

// Quiet profile
// Data Source: https://docs.nvidia.com/jetson/archives/r35.4.1/DeveloperGuide/text/SD/PlatformPowerAndPerformance/JetsonXavierNxSeriesAndJetsonAgxXavierSeries.html
func (p profileXavier) getQuietProfile() coolingMode {
	modeQuiet := coolingMode{
		name: "quiet",
		// Must be sorted!
		points: [][]int{
			{0,0},
			{50,77},
			{63,120},
			{72,160},
			{81,255},
			{140,255},
			{150,255},
			{160,255},
			{170,255},
			{180,255},
		},
	}
	return modeQuiet
}

// Cool profile
// Data Source: https://docs.nvidia.com/jetson/archives/r35.4.1/DeveloperGuide/text/SD/PlatformPowerAndPerformance/JetsonXavierNxSeriesAndJetsonAgxXavierSeries.html
func (p profileXavier) getCoolProfile() coolingMode {
	modeCool := coolingMode{
		name: "cool",
		// Must be sorted!
		points: [][]int{
			{35,77},
			{53,120},
			{62,160},
			{73,255},
			{140,255},
			{150,255},
			{160,255},
			{170,255},
			{180,255},
		},
	}
	return modeCool
}

// Jetson Orin device model
func (p profileOrin) Model() string {
	return "Jetson Orin"
}

// Quiet profile (Orin series)
// Data Source: https://docs.nvidia.com/jetson/archives/r35.4.1/DeveloperGuide/text/SD/PlatformPowerAndPerformance/JetsonOrinNanoSeriesJetsonOrinNxSeriesAndJetsonAgxOrinSeries.html#fan-profile-control
func (p profileOrin) getQuietProfile() coolingMode {
	modeQuiet := coolingMode{
		name: "quiet",
		// Must be sorted!
		points: [][]int{
			{0,66},
			{10,66},
			{11,171},
			{23,171},
			{60,255},
			{105,255},
		},
	}
	return modeQuiet
}

// Cool profile (Orin Series)
// Data Source: https://docs.nvidia.com/jetson/archives/r35.4.1/DeveloperGuide/text/SD/PlatformPowerAndPerformance/JetsonOrinNanoSeriesJetsonOrinNxSeriesAndJetsonAgxOrinSeries.html#fan-profile-control
func (p profileOrin) getCoolProfile() coolingMode {
	modeCool := coolingMode{
		name: "cool",
		// Must be sorted!
		points: [][]int{
			{0,66},
			{10,66},
			{11,215},
			{30,215},
			{60,255},
			{105,255},
		},
    }
	return modeCool
}

// Check if the temperature file exist for a thermal zone
func checkThermalZone(tzone int) bool {
	if _, err := os.Stat(getThermalDevice(tzone)); err == nil {
		return true
	}
	return false
}

// Return the thermal zone temperature file
func getThermalDevice(tzone int) string {
	return fmt.Sprintf(thermalDevice, tzone)
}

// Identify device model and return PWM profile accordingly
// Reference: https://docs.nvidia.com/jetson/archives/r35.4.1/DeveloperGuide/text/HR/JetsonEepromLayout.html
func getDeviceProfile() (deviceProfiles, error) {
	asset, err := ioutil.ReadFile(assetTagSysFs)
	if err != nil {
		return nil, err
	}
	assetTag := string(asset)

	// Extract model from Asset TAG
	reAT := regexp.MustCompile("699-[0-9]([0-9]{4})-([0-9]{4})-([0-9]{3})( .*)")
	if !reAT.MatchString(assetTag) {
		return nil, fmt.Errorf("Asset TAG doesn't match any known model")
	}
	str := strings.TrimSpace(reAT.ReplaceAllString(assetTag, "$1"))

	// Decode model
	devIDs := map[string]deviceProfiles{
		"3767": profileOrin{},
		"3701": profileOrin{},
		"3768": profileOrin{},
		"3737": profileOrin{},
		"3668": profileXavier{},
		"2888": profileXavier{},
		"3509": profileXavier{},
		"2822": profileXavier{},
	}
	dev, ok := devIDs[str]
	if !ok {
		return nil, fmt.Errorf("Unknown Jetson model")
	}

	return dev, nil
}

// Search for the PWM Fan device
func getFANDevice() (string, error) {
	entries, err := os.ReadDir(fanSysDir)
	if err != nil {
		return "", err
	}
	// We just need the first entry (most probably the only one)
	nfans := len(entries)
	if nfans >= 1 {
		dev := fanSysDir + entries[0].Name() + "/pwm1"
		if nfans > 1 {
			// Just issue a warning if we found more than one PWM device
			fmt.Fprintf(os.Stderr, "WARNING: Found more than one FAN, controlling only the first one.")
		}
		return dev, nil
	}
	return "", nil
}

// Read and convert (to Celsius) the temperature from a thermal device
func (pwm fanCTRL) readTemp() (int, error) {
	data, err := os.ReadFile(pwm.devThermal)
	if err != nil {
		return -1, err
	}

	str := string(data[:len(data)-1])
	temp, errconv := strconv.Atoi(str)
	if errconv != nil {
		return -1, errconv
	}

	return temp/1000, nil
}

// Set PWM value of a FAN device
func (pwm fanCTRL) setPWM(pwmValue int) error {
	errF := os.WriteFile(pwm.devPWM, []byte(strconv.Itoa(pwmValue)), 0644)
	if errF != nil {
		return fmt.Errorf("Fail to change FAN speed")
	}
	return nil
}

// Perform the controlling iteration
func (pwm fanCTRL) controlPWM() error {
	temp, errT := pwm.readTemp()
	if errT != nil {
		return fmt.Errorf("Fail to read temperature!")
	}

	pwmValue := maxPWM // Set to maximum
	for _, v := range pwm.cmode.points {
		if temp < v[0] {
			break
		} else {
			pwmValue = v[1]
		}
	}

	return pwm.setPWM(pwmValue)
}

// Controlling loop
func (pwm fanCTRL) run(ctx context.Context) error {
	ticker := time.NewTicker(time.Duration(pwm.checkInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil

		case <-ticker.C:
			err := pwm.controlPWM()
			if err != nil {
				fmt.Println("Error:", err)
			}
		}
	}
}

// Stop FAN controller and set PWM to maximum
func (pwm fanCTRL) finish() error {
	fmt.Println("Finishing FAN controller")
	return pwm.setPWM(maxPWM)
}

func main() {
	var mode string
	var tzone int
	var checkInterval int
	var cmode coolingMode

	// Build and validate the command line
	flag.Usage = func() {
		fmt.Printf("FAN PWM controller for Jetson devices\n\n")
		fmt.Printf("Use:\n    %s [-m <mode>] [-t <thermal_zone>] [-i <pooling_time>]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.StringVar(&mode, "m", "quiet", "Cooling profile: quiet or cool")
	flag.IntVar(&tzone, "t", 0, "Thermal zone number")
	flag.IntVar(&checkInterval, "i", 2, "Pooling time (in seconds)")
	flag.Parse()

	// Identify device and get PWM profiles
	dev, err := getDeviceProfile()
	if err != nil {
		dev = profileXavier{}
		fmt.Fprintf(os.Stderr, "Device could not be identified, using %s profile\n", dev.Model())
	}

	switch (mode) {
	case "quiet":
		cmode = dev.getQuietProfile()
	case "cool":
		cmode = dev.getCoolProfile()
	default:
		fmt.Fprintf(os.Stderr, "Invalid cooling profile: %s\n", mode)
		os.Exit(1)
	}
	if !checkThermalZone(tzone) {
		fmt.Fprintf(os.Stderr, "Invalid thermal zone: %d\n", tzone)
		os.Exit(1)
	}
	if checkInterval <= 0 || checkInterval >= 60 {
		fmt.Fprintf(os.Stderr, "Invalid pooling time: %d\n", checkInterval)
		os.Exit(1)
	}

	fmt.Printf("Starting FAN controller (device identified: %s)\n", dev.Model())

	// Search the PWM fan device
	fanDevice, err := getFANDevice()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not found a FAN device to control\n")
		os.Exit(1)
	}

	// FAN controller
	pwmCTRL := fanCTRL{
		devPWM: fanDevice,
		devThermal: getThermalDevice(tzone),
		cmode: cmode,
		checkInterval: checkInterval,
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGHUP)
	defer func(c chan<- os.Signal) {
		signal.Stop(c)
		cancel()
	}(sigChan)

	go func() {
		for {
			select {
			case s := <-sigChan:
				if (s == os.Interrupt) {
					cancel()
					if err := pwmCTRL.finish(); err != nil {
						fmt.Println("Error:", err)
					}
					os.Exit(0)
				}
			case <-ctx.Done():
				if err := pwmCTRL.finish(); err != nil {
					fmt.Println("Error:", err)
				}
			}
		}
	}()

	if err := pwmCTRL.run(ctx); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if err := pwmCTRL.finish(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
