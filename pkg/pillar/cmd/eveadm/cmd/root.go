package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
	"strconv"
	"time"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var cfgFile string

//Timeout of running command
var Timeout time.Duration
var timeout string

//Verbose mode
var Verbose bool

//RootCmd is root of cobra
var RootCmd *cobra.Command

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "eveadm",
	Short: "A brief description of your application",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//	Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.eveadm.yaml)")

	rootCmd.PersistentFlags().StringVarP(&timeout, "timeout", "t", "", "Actions timeout in minutes")
	viper.BindPFlag("timeout", rootCmd.PersistentFlags().Lookup("timeout"))

	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose execution")
	viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	RootCmd = rootCmd
	Run = run
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".eveadm" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".eveadm")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	Verbose = viper.GetBool("verbose")
	timeout = viper.GetString("timeout")
	if len(timeout) > 0 {
		minutes, err := strconv.Atoi(timeout)
		Timeout = time.Duration(minutes) * time.Minute
		if err != nil {
			fmt.Println(err)
		}
	}
	if Verbose {
		fmt.Println("Timeout:", Timeout)
	}
}
