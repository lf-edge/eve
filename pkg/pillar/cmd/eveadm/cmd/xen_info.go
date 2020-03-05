package cmd

import (
	"log"

	"github.com/spf13/cobra"
)

// xenInfoCmd represents the info command
var xenInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Run shell command with arguments in 'info' action on 'xen' mode",
	Long: `
Run shell command with arguments in 'info' action on 'xen' mode. For example:

eveadm xen info uuid
eveadm xen info --domname name
`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		isDomid, err := cmd.Flags().GetBool("domname")
		arg := args[0]
		var envs string
		if isDomid {
			xenctx.containerName = arg
			args, envs, err = xenctx.xenInfoDomidToCmd()
		} else {
			xenctx.containerUUID = arg
			args, envs, err = xenctx.xenInfoToCmd()
		}
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	xenCmd.AddCommand(xenInfoCmd)
	xenInfoCmd.Flags().Bool("domname", false, "Work with name")
}
