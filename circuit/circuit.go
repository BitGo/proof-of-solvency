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
type Balance struct {
	Bitcoin  frontend.Variable
	Ethereum frontend.Variable
}

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

	// TODO(BTC-2038): don't manually enumerate
	// Verifies each account has value between 0 and 2^64 - 1.
	// If we incorporate bigger accounts, we can go up to 128 bits safely.
	ranger.Check(balances.Bitcoin, 64)
	ranger.Check(balances.Ethereum, 64)
}

func addBalance(api frontend.API, a, b Balance) Balance {
	// TODO(BTC-2038): don't manually enumerate
	return Balance{
		Bitcoin:  api.Add(a.Bitcoin, b.Bitcoin),
		Ethereum: api.Add(a.Ethereum, b.Ethereum),
	}
}

// hashBalance computes the MiMC hash of the balance. goConvertBalanceToBytes is the Go equivalent,
// although it does not actually do the hashing step.
func hashBalance(hasher mimc.MiMC, balances Balance) (hash frontend.Variable) {
	hasher.Reset()
	// TODO(BTC-2038): don't manually enumerate
	hasher.Write(balances.Bitcoin, balances.Ethereum)
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
	// TODO(BTC-2038): don't manually enumerate
	api.AssertIsEqual(a.Bitcoin, b.Bitcoin)
	api.AssertIsEqual(a.Ethereum, b.Ethereum)
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
	var runningBalance = Balance{Bitcoin: 0, Ethereum: 0}
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
