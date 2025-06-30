package cli

import (
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/core"
	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:   "verify [BatchCount]",
	Short: "Performs full verification of using the public data in 'out/public/' and the user data in 'out/secret/'",
	Long: "Performs full verification of all generated proofs using the public data in 'out/public/' and the user data in 'out/user/'.\n" +
		"Intended to be used after proof generation to validate the proofs were generated correctly.\n" +
		"Verifies: \n" +
		" 1) Each proof is valid (the zk-SNARK verification passes).\n" +
		" 2) Each bottom level and mid level proof's merkle path leads to its corresponding upper level proof's merkle root.\n" +
		" 3) Each proof has merkle nodes that accurately represent the tree of the merkle root.\n" +
		" 4) Each account was included in at least one bottom level proof.\n" +
		" 5) The AssetSum published in the top level proof is indeed the sum hashed in MerkleRootWithAssetSumHash.\n" +
		"The command takes 1 argument: the number of batches.",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		batchCount, err := strconv.Atoi(args[0])
		if err != nil {
			fmt.Println("Error parsing batchCount:", err)
			return
		}
		core.VerifyFull(batchCount)
		println("Verification succeeded!")
	},
}

var userVerifyCmd = &cobra.Command{
	Use:   "userverify [path/to/userinfo.json]",
	Short: "Verify the provided user account was included in the provided proofs and proofs are valid.",
	Long: "Verifies the provided user account was included in the provided proofs and proofs are valid.\n" +
		"This is the main verification tool by which one can verify they were included in the total liability sum and no negative accounts were included in the sum.\n" +
		"Verifies:\n" +
		"1) The given account was included in the bottom level proof provided\n" +
		"2) The bottom level proof provided was included in the mid level proof provided\n" +
		"3) The mid level proof provided was included in the top level proof provided\n" +
		"4) The top level proof provided matches the asset sum published\n" +
		"5) The chain of proofs is valid, meaning:\n" +
		"---> Your account was included in the asset sum for the low level proof.\n" +
		"---> The low level proof was included in the asset sum for the mid level proof.\n" +
		"---> The mid level proof was included in the asset sum for the high level proof.\n" +
		"---> There were no accounts with overflowing balances or negative balances included in any of the asset sums.",
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		userVerificationElements := core.ReadDataFromFile[core.UserVerificationElements](args[0])
		core.VerifyUser(userVerificationElements)
		println("User verification succeeded!")
	},
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(userVerifyCmd)
}
