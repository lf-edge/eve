package main

import (
	"os"

	"github.com/Sirupsen/logrus"
	"github.com/codegangsta/cli"
	"github.com/docker/docker/cli/config"
)

// will be filled in at compile time
var gitCommit = ""

const (
	version = "0.7.0"
	usage   = "inspect and push manifest list images to a registry"
)

func main() {
	app := cli.NewApp()
	app.Name = os.Args[0]
	app.Version = version + " (commit: " + gitCommit + ")"
	app.Usage = usage
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:  "debug",
			Usage: "enable debug output",
		},
		cli.StringFlag{
			Name:  "username",
			Value: "",
			Usage: "registry username",
		},
		cli.StringFlag{
			Name:  "password",
			Value: "",
			Usage: "registry password",
		},
		cli.StringFlag{
			Name:  "docker-cfg",
			Value: config.Dir(),
			Usage: "Docker's cli config for auth",
		},
	}
	app.Before = func(c *cli.Context) error {
		if c.GlobalBool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		} else {
			logrus.SetLevel(logrus.WarnLevel)
		}
		return nil
	}
	// currently support inspect and pushml
	app.Commands = []cli.Command{
		inspectCmd,
		pushCmd,
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
