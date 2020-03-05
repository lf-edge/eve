package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"log"
)

// rktStartCmd represents the start command
var rktStartCmd = &cobra.Command{
	Use:   "start id",
	Short: "Run shell command with arguments in 'start' action on 'rkt' mode",
	Long: `Run shell command with arguments in 'start' action on 'rkt' mode. For example:

eveadm rkt start uuid
`, Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		if rktctx.stage1Type == "xen" {
			rktctx.containerUUID = arg
			args, envs, err := rktctx.rktStartToCmd()
			if err != nil {
				log.Fatalf("Error in obtain params in %s", cmd.Name())
			}
			Run(cmd, Timeout, args, envs)
		} else {
			fmt.Println("Not implemented for common type of stage1")
		}
	},
}

func init() {
	rktCmd.AddCommand(rktStartCmd)
}
