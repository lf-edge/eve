package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// rktDeleteCmd represents the delete command
var rktDeleteCmd = &cobra.Command{
	Use:   "delete uuid",
	Short: "Run shell command with arguments in 'delete' action on 'rkt' mode",
	Long: `
Run shell command with arguments in 'delete' action on 'rkt' mode. For example:

eveadm rkt delete uuid`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		isImage, err := cmd.Flags().GetBool("image")
		if err != nil {
			log.Fatalf("Error in get param image in %s", cmd.Name())
		}
		var envs string
		if isImage {
			rktctx.imageUUID = arg
			args, envs, err = rktctx.rktDeleteImageToCmd()
		} else {
			rktctx.containerUUID = arg
			args, envs, err = rktctx.rktDeleteToCmd()
		}
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	rktCmd.AddCommand(rktDeleteCmd)
	rktDeleteCmd.Flags().BoolP("image", "i", false, "Work with images")
}
