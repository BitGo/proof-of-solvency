// Package circuit provides functionality for directly interacting with the zero-knowledge proofs
// as well as functions to replicate that functionality in Go.
package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/rangecheck"
)

// TreeDepth corresponds to a maximum of 1024 accounts per bottom level proof,
// and 1024 proofs per higher level proof
const TreeDepth = 10

// Balance is an input to the circuit and is only used in this package. GoBalance is preferred elsewhere.
type Balance []frontend.Variable

// Account is an input to the circuit and is only used in this package. GoAccount is preferred elsewhere.
type Account struct {
	UserId  frontend.Variable
	Balance Balance
}

// Circuit is the input to the proof. A complete Circuit generates a proof, and the public elements of
// the Circuit can be used to verify the proof.
type Circuit struct {
	Accounts                   []Account         `gnark:""`
	AssetSum                   Balance           `gnark:""`
	MerkleRoot                 frontend.Variable `gnark:",public"`
	MerkleRootWithAssetSumHash frontend.Variable `gnark:",public"`
}

// Util to get power of two.
func powOfTwo(n int) int {
	return 1 << n
}

// Adds constraints to verify each balance is a value between [0, 2^128 - 1].
func assertBalanceNonNegativeAndNonOverflow(api frontend.API, balances Balance) {
	ranger := rangecheck.New(api)
	for _, balance := range balances {
		ranger.Check(balance, 128)
	}
}

// Returns sum of 2 balances.
func addBalance(api frontend.API, a, b Balance) Balance {
	// Enforce balances have same length as AssetSymbols. This is done as a panic instead of a circuit
	// constraint as it is not necessary for the proofs to be valid - the worst an exchange can do is
	// add fake accounts with a different size balance array, which will only increase the liabilities.
	// (User account balances cannot be tampered with due to the additional Merkle Tree hash verification).
	if len(a) != GetNumberOfAssets() || len(b) != GetNumberOfAssets() {
		panic("balances must have the same length as assets")
	}
	summedBalance := make([]frontend.Variable, len(a))
	for i := range a {
		summedBalance[i] = api.Add(a[i], b[i])
	}
	return summedBalance
}

// hashBalance computes the MiMC hash of the balance. goConvertBalanceToBytes is the Go equivalent,
// although it does not actually do the hashing step.
func hashBalance(hasher mimc.MiMC, balances Balance) (hash frontend.Variable) {
	// enforce balances have same length as AssetSymbols (see note in addBalance)
	if len(balances) != GetNumberOfAssets() {
		panic("balances must have the same length as assets")
	}
	hasher.Reset()
	hasher.Write(balances[:]...)
	return hasher.Sum()
}

// hashAccount computes the MiMC hash of the account. GoComputeMiMCHashForAccount is the Go equivalent for general use.
func hashAccount(hasher mimc.MiMC, account Account) (hash frontend.Variable) {
	hasher.Reset()
	hasher.Write(account.UserId, hashBalance(hasher, account.Balance))
	return hasher.Sum()
}

// computeMerkleRootFromAccounts computes the Merkle root from the accounts.
// GoComputeMerkleRootFromAccounts is the Go equivalent for general use.
func computeMerkleRootFromAccounts(hasher mimc.MiMC, accounts []Account) (rootHash frontend.Variable) {
	// store hashes of accounts in an array (pad with 0's to reach 2^TreeDepth nodes)
	nodes := make([]frontend.Variable, powOfTwo(TreeDepth))
	for i := 0; i < powOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = hashAccount(hasher, accounts[i])
		} else {
			nodes[i] = 0
		}
	}

	// iteratively calculate hashes of parent nodes from bottom level to root
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < powOfTwo(i); j++ {
			hasher.Reset()
			hasher.Write(nodes[j*2], nodes[j*2+1])
			nodes[j] = hasher.Sum()
		}
	}
	return nodes[0]
}

// Adds constraints to verify the given balances are equal.
func assertBalancesAreEqual(api frontend.API, a, b Balance) {
	// enforce balances have same length as AssetSymbols (see note in addBalance)
	if len(a) != GetNumberOfAssets() || len(b) != GetNumberOfAssets() {
		panic("balances must have the same length as assets")
	}

	// add constraints
	for i := range a {
		api.AssertIsEqual(a[i], b[i])
	}
}

// Define defines the actual circuit.
func (circuit *Circuit) Define(api frontend.API) error {
	// This is not an essential part of the proof, because adding additional accounts
	// can only increase the AssetSum and not decrease it.
	// The creator of the proof can already do that by adding phony accounts with arbitrary balances,
	// so violating this does not affect the security of the proof and does not introduce additional caveats.
	// Thus, it is an inline check and not a constraint.
	if len(circuit.Accounts) > powOfTwo(TreeDepth) {
		panic("number of accounts exceeds the maximum number of leaves in the Merkle tree")
	}

	// initialize running balance
	var runningBalance = make([]frontend.Variable, GetNumberOfAssets())
	for i := range runningBalance {
		runningBalance[i] = frontend.Variable(0)
	}

	// create hasher
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}

	// for each account, add balance to running balance and assert balance in correct range
	for i := 0; i < len(circuit.Accounts); i++ {
		account := circuit.Accounts[i]
		assertBalanceNonNegativeAndNonOverflow(api, account.Balance)
		runningBalance = addBalance(api, runningBalance, account.Balance)
	}

	// assert total balance = sum, merkle root matches, and merkle root with sum matches
	assertBalancesAreEqual(api, runningBalance, circuit.AssetSum)
	root := computeMerkleRootFromAccounts(hasher, circuit.Accounts)
	api.AssertIsEqual(root, circuit.MerkleRoot)
	rootWithSum := hashAccount(hasher, Account{UserId: circuit.MerkleRoot, Balance: circuit.AssetSum})
	api.AssertIsEqual(rootWithSum, circuit.MerkleRootWithAssetSumHash)

	return nil
}
