package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// xenUpdateCmd represents the update command
var xenUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Run shell command with arguments in 'update' action on 'xen' mode",
	Long: `Run shell command with arguments in 'update' action on 'xen' mode. For example:

eveadm xen update`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Not implemented now")
	},
}

func init() {
	xenCmd.AddCommand(xenUpdateCmd)
}
