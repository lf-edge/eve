package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// rktDeleteCmd represents the delete command
var rktGCCmd = &cobra.Command{
	Use:   "gc",
	Short: "Run shell command with arguments in 'gc' action on 'rkt delete' mode",
	Long: `
Run shell command with arguments in 'gc' action on 'rkt delete' mode. For example:

eveadm rkt delete gc`,
	Run: func(cmd *cobra.Command, args []string) {
		isImage, err := cmd.Flags().GetBool("image")
		if err != nil {
			log.Fatalf("Error in get param image in %s", cmd.Name())
		}
		var envs string
		if isImage {
			args, envs, err = rktctx.rktDeleteGCImageToCmd()
		} else {
			args, envs, err = rktctx.rktDeleteGCToCmd()
		}
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	rktDeleteCmd.AddCommand(rktGCCmd)
	rktGCCmd.Flags().BoolP("image", "i", false, "Work with images")
	rktGCCmd.Flags().StringVar(&rktctx.gcGracePeriod, "grace-period", "", "Garbage grace period")
}
