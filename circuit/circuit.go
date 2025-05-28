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
// We can't make this a fixed size array (if we do, we'll need to update this everytime we add a new asset).
// Two options (I can think of):
//  1. Just enforce through panics.
//  2. Add extra constraints to the circuit to ensure that the length of the balance matches the number of assets.
//     This option would also need an index associated with each asset, making it even more inefficient.
//
// Currently, we use the first option - we don't really need to use the second one, unless we find that without
// those additional constraints, there could be a security/trust issue.
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

func PowOfTwo(n int) (result int) {
	result = 1
	for i := 0; i < n; i++ {
		result *= 2
	}
	return result
}

func assertBalanceNonNegativeAndNonOverflow(api frontend.API, balances Balance) {
	ranger := rangecheck.New(api)
	for _, balance := range balances {
		// Verifies each account has value between 0 and 2^64 - 1.
		// If we incorporate bigger accounts, we can go up to 128 bits safely.
		ranger.Check(balance, 64)
	}
}

func addBalance(api frontend.API, a, b Balance) Balance {
	// enforce all have the same length as assetsymbols
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
	// do we need to enforce this here?
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
func computeMerkleRootFromAccounts(api frontend.API, hasher mimc.MiMC, accounts []Account) (rootHash frontend.Variable) {
	nodes := make([]frontend.Variable, PowOfTwo(TreeDepth))
	for i := 0; i < PowOfTwo(TreeDepth); i++ {
		if i < len(accounts) {
			nodes[i] = hashAccount(hasher, accounts[i])
		} else {
			nodes[i] = 0
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < PowOfTwo(i); j++ {
			hasher.Reset()
			hasher.Write(nodes[j*2], nodes[j*2+1])
			nodes[j] = hasher.Sum()
		}
	}
	return nodes[0]
}

func assertBalancesAreEqual(api frontend.API, a, b Balance) {
	if len(a) != GetNumberOfAssets() || len(b) != GetNumberOfAssets() {
		panic("balances must have the same length as assets")
	}
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
	if len(circuit.Accounts) > PowOfTwo(TreeDepth) {
		panic("number of accounts exceeds the maximum number of leaves in the Merkle tree")
	}
	var runningBalance = make([]frontend.Variable, GetNumberOfAssets())
	for i := range runningBalance {
		runningBalance[i] = frontend.Variable(0)
	}

	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		panic(err)
	}
	for i := 0; i < len(circuit.Accounts); i++ {
		account := circuit.Accounts[i]
		assertBalanceNonNegativeAndNonOverflow(api, account.Balance)
		runningBalance = addBalance(api, runningBalance, account.Balance)
	}
	assertBalancesAreEqual(api, runningBalance, circuit.AssetSum)
	root := computeMerkleRootFromAccounts(api, hasher, circuit.Accounts)
	api.AssertIsEqual(root, circuit.MerkleRoot)
	rootWithSum := hashAccount(hasher, Account{UserId: circuit.MerkleRoot, Balance: circuit.AssetSum})
	api.AssertIsEqual(rootWithSum, circuit.MerkleRootWithAssetSumHash)
	return nil
}
