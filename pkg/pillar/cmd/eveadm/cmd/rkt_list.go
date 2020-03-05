package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// rktListCmd represents the list command
var rktListCmd = &cobra.Command{
	Use:   "list",
	Short: "Run shell command with arguments in 'list' action on 'rkt' mode",
	Long: `
Run shell command with arguments in 'list' action on 'rkt' mode. For example:

eveadm rkt list --image
eveadm rkt list
`,
	Run: func(cmd *cobra.Command, args []string) {
		isImage, err := cmd.Flags().GetBool("image")
		if err != nil {
			log.Fatalf("Error in get param image in %s", cmd.Name())
		}
		fields, err := cmd.Flags().GetString("fields")
		if err != nil {
			log.Fatalf("Error in get param fields in %s", cmd.Name())
		}
		rktctx.fields = fields
		var envs string
		if isImage {
			args, envs, err = rktctx.rktListImageToCmd()
		} else {
			args, envs, err = rktctx.rktListToCmd()
		}
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	rktCmd.AddCommand(rktListCmd)
	rktListCmd.Flags().BoolVar(&rktctx.noLegend, "no-legend", false, "Suppress legend")
	rktListCmd.Flags().BoolP("image", "i", false, "Work with images")
	rktListCmd.Flags().String("fields", "", "Fields to return")
}
