package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// xenCmd represents the xen command
var xenCmd = &cobra.Command{
	Use:   "xen",
	Short: "Xen mode",
	Long: `
Execute actions on 'xen' mode. For example:

eveadm xen list
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("xen called")
	},
}

func init() {
	rootCmd.AddCommand(xenCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// xenCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// xenCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
