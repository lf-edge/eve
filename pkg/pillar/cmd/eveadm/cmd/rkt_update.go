package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rktUpdateCmd represents the update command
var rktUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Run shell command with arguments in 'update' action on 'rkt' mode",
	Long: `Run shell command with arguments in 'update' action on 'rkt' mode. For example:

eveadm rkt update ps x`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Not implemented now")
	},
}

func init() {
	rktCmd.AddCommand(rktUpdateCmd)
}
