package cmd

import (
	"github.com/spf13/cobra"
	"log"
)

// rktCreateCmd represents the create command
var rktCreateCmd = &cobra.Command{
	Use:   "create url/uuid",
	Short: "Run shell command with arguments in 'create' action on 'rkt' mode",
	Long: `
Run shell command with arguments in 'create' action on 'rkt' mode. For example:

eveadm rkt create --image url
eveadm rkt create image_uuid
`, Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		arg := args[0]
		isImage, err := cmd.Flags().GetBool("image")
		if err != nil {
			log.Fatalf("Error in get param image in %s", cmd.Name())
		}
		var envs string
		if isImage {
			rktctx.imageURL = arg
			args, envs, err = rktctx.rktCreateImageToCmd()
		} else {
			rktctx.imageUUID = arg
			args, envs, err = rktctx.rktCreateToCmd()
		}
		if err != nil {
			log.Fatalf("Error in obtain params in %s", cmd.Name())
		}
		Run(cmd, Timeout, args, envs)
	},
}

func init() {
	rktCmd.AddCommand(rktCreateCmd)
	rktCreateCmd.Flags().BoolP("image", "i", false, "Work with images")
	rktCreateCmd.Flags().StringVar(&rktctx.uuidFile, "uuid-file-save", "", "File to save uuid")
	rktCreateCmd.Flags().StringVar(&rktctx.xenCfgFilename, "xen-cfg-filename", "", "File with xen cfg for stage1")
	rktCreateCmd.Flags().StringVar(&rktctx.stage1Path, "stage1-path", "/usr/sbin/stage1-xen.aci", "Stage1 path")
	rktCreateCmd.Flags().StringVar(&rktctx.stage2MP, "stage2-mnt-pts", "", "Stage2 mount points file")
	rktCreateCmd.Flags().Var(&rktctx.flagExplicitEnv, "set-env", "environment variable to set for all the apps in the form key=value")
	//Workaround to start in Ubuntu
	rktCreateCmd.Flags().BoolVar(&rktctx.noOverlay, "no-overlay", false, "Run without overlay")

	rktCreateCmd.Flags().BoolVar(&rktctx.runPaused, "paused", true, "Run paused")
}
