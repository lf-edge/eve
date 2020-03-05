package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// rktCmd represents the rkt command
var rktCmd = &cobra.Command{
	Use:   "rkt",
	Short: "RKT mode",
	Long: `
Execute actions on 'rkt' mode. For example:

eveadm rkt list
`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("rkt called")
	},
}

func init() {
	rootCmd.AddCommand(rktCmd)
	rootCmd.PersistentFlags().StringVar(&rktctx.dir, "dir", "", "RKT data dir")
	rootCmd.PersistentFlags().StringVar(&rktctx.insecureOptions, "insecure-options", "image", "RKT insecure-options")
	rootCmd.PersistentFlags().StringVar(&rktctx.stage1Type, "stage1-type", "xen", "Type of stage1 (xen or general)")
}
