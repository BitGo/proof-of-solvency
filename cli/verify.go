package cli

import (
	"bitgo.com/proof_of_reserves/circuit"
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/core"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [BatchCount]",
	Short: "Verifies proofs using the public data in 'out/public/' and the user data in 'out/user/'",
	Long:  "Verifies proofs using the public data in 'out/public/' and the user data in 'out/user/'. This function takes 1 argument: the number of batches.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		batchCount, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Error parsing batchCount:", err)
			return
		}
		account := core.ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")
		core.Verify(batchCount, account)
		println("Verification succeeded!")
	},
}

var userVerifyCmd = &cobra.Command{
	Use:   "userverify [path/to/useraccount.json] [path/to/bottomlevelproof.json] [path/to/midlevelproof.json] [path/to/toplevelproof.json]",
	Short: "Verify your account was included in the proofs and the proofs are sufficient.",
	Long: "This is intended to be the main verification path, requiring O(log n) time to verify proof of solvency. " +
		"This verification path verifies that \n" +
		"1) Your account was included in the bottom level proof you were provided\n" +
		"2) The bottom level proof you were provided was included in the mid level proof you were provided\n" +
		"3) The mid level proof you were provided was included in the top level proof you were provided\n" +
		"4) The top level proof you were provided matches the asset sum you were provided\n" +
		"5) The chain of proofs is valid (i.e., your account was included in the asset sum for the low level proof, " +
		"the low level proof was included in the asset sum for the mid level proof, " +
		"the mid level proof was included in the asset sum for the high level proof, and " +
		"there were no accounts with overflowing balances or negative balances included in any of the asset sums.",
	Args: cobra.ExactArgs(4),
	Run: func(cmd *cobra.Command, args []string) {
		userAccount := core.ReadDataFromFile[circuit.GoAccount](args[0])
		bottomLevelProof := core.ReadDataFromFile[core.CompletedProof](args[1])
		midLevelProof := core.ReadDataFromFile[core.CompletedProof](args[2])
		topLevelProof := core.ReadDataFromFile[core.CompletedProof](args[3])
		core.VerifyProofPath(circuit.GoComputeMiMCHashForAccount(userAccount), bottomLevelProof, midLevelProof, topLevelProof)
		println("Verification path succeeded!")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(userVerifyCmd)
}
