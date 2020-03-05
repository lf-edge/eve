package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// rktStopCmd represents the stop command
var rktStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Run shell command with arguments in 'stop' action on 'rkt' mode",
	Long: `Run shell command with arguments in 'stop' action on 'rkt' mode. For example:

eveadm rkt stop uuid
`, Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		rktctx.containerUUID = args[0]
		force, err := cmd.Flags().GetBool("force")
		if err != nil {
			log.Fatalf("Error in get param force in %s", cmd.Name())
		}
		rktctx.force = force
		args, envs, err := rktctx.rktStopToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	rktCmd.AddCommand(rktStopCmd)
	rktStopCmd.Flags().BoolP("force", "f", false, "Force stop")
}
