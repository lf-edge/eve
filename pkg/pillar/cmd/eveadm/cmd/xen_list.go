package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// xenListCmd represents the list command
var xenListCmd = &cobra.Command{
	Use:   "list",
	Short: "Run shell command with arguments in 'list' action on 'xen' mode",
	Long: `
Run shell command with arguments in 'list' action on 'xen' mode. For example:

eveadm xen list
`,
	Run: func(cmd *cobra.Command, args []string) {
		args, envs, err := xenctx.xenListToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenListCmd)
}
