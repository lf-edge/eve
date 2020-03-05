package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// xenStartCmd represents the start command
var xenStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Run shell command with arguments in 'start' action on 'xen' mode",
	Long: `Run shell command with arguments in 'start' action on 'xen' mode. For example:

eveadm xen start uuid`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		xenctx.containerUUID = arg
		args, envs, err := xenctx.xenStartToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenStartCmd)
}
