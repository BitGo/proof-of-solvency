package cli

import (
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/core"
	"github.com/spf13/cobra"
)

var proveCmd = &cobra.Command{
	Use:   "prove [BatchCount]",
	Short: "Generates proofs using the secret data in 'out/secret/'",
	Long:  "Generates proofs using the secret data in 'out/secret/'. This function takes 1 argument: the number of batches.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		batchCount, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Error parsing batchCount:", err)
			return
		}
		core.Prove(batchCount, core.OUT_DIR)
	},
}

func init() {
	rootCmd.AddCommand(proveCmd)
}
