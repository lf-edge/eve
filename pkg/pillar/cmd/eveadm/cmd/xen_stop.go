package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// xenStopCmd represents the stop command
var xenStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Run shell command with arguments in 'stop' action on 'xen' mode",
	Long: `Run shell command with arguments in 'stop' action on 'xen' mode. For example:

eveadm xen stop uuid`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			log.Fatalf("Error in get param force in %s", cmd.Name())
		}
		xenctx.force = force
		xenctx.containerUUID = arg
		args, envs, err := xenctx.xenStopToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenStopCmd)
	xenStopCmd.Flags().BoolP("force", "f", false, "Force stop")
}
