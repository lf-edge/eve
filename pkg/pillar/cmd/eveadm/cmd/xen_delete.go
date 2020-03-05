package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// xenDeleteCmd represents the delete command
var xenDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Run shell command with arguments in 'delete' action on 'xen' mode",
	Long: `
Run shell command with arguments in 'delete' action on 'xen' mode. For example:

eveadm xen delete uuid`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		xenctx.containerUUID = arg
		args, envs, err := xenctx.xenDeleteToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenDeleteCmd)
}
