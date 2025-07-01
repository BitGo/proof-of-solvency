package cli

import (
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/core"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate [BatchCount] [AccountsPerBatch]",
	Short: "Populates 'out/secret/' with test data.",
	Long:  "Populates 'out/secret/' with test data. This function takes 2 arguments: the number of batches and the accounts per batch.",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		batchCount, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Error parsing batchCount:", err)
			return
		}
		accountsPerBatch, err := strconv.Atoi(args[1])
		if err != nil {
			fmt.Println("Error parsing accountsPerBatch:", err)
			return
		}
		core.GenerateData(batchCount, accountsPerBatch, core.OUT_DIR)
	},
}

func init() {
	rootCmd.AddCommand(generateCmd)
}
