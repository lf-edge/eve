package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// xenCreateCmd represents the create command
var xenCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Run shell command with arguments in 'create' action on 'xen' mode",
	Long: `
Run shell command with arguments in 'create' action on 'xen' mode. For example:

eveadm xen create --xen-cfg-filename=dom.cfg
`,
	Run: func(cmd *cobra.Command, args []string) {
		args, envs, err := xenctx.xenCreateToCmd()
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenCreateCmd)
	xenCreateCmd.Flags().StringVar(&xenctx.xenCfgFilename, "xen-cfg-filename", "", "File with xen cfg for stage1")
	xenCreateCmd.Flags().BoolVarP(&xenctx.runPaused, "paused", "p", true, "Run paused")
	err := cobra.MarkFlagRequired(xenCreateCmd.Flags(), "xen-cfg-filename")
	if err != nil {
		log.Fatalf("Error in getting required flags: %s", err.Error())
	}
}
