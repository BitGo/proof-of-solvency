package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/rangecheck"
)

const TreeDepth = 10

type Balance struct {
	Bitcoin  frontend.Variable
	Ethereum frontend.Variable
}

type Account struct {
	UserId  frontend.Variable
	Balance Balance
}

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

	// TODO: don't manually enumerate
	ranger.Check(balances.Bitcoin, 64)
	ranger.Check(balances.Ethereum, 64)
}

func addBalance(api frontend.API, a, b Balance) Balance {
	return Balance{
		Bitcoin:  api.Add(a.Bitcoin, b.Bitcoin),
		Ethereum: api.Add(a.Ethereum, b.Ethereum),
	}
}

func hashBalance(hasher mimc.MiMC, balances Balance) (hash frontend.Variable) {
	hasher.Reset()
	// TODO: don't manually enumerate
	hasher.Write(balances.Bitcoin, balances.Ethereum)
	return hasher.Sum()
}

func hashAccount(hasher mimc.MiMC, account Account) (hash frontend.Variable) {
	hasher.Reset()
	hasher.Write(account.UserId, hashBalance(hasher, account.Balance))
	return hasher.Sum()
}

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
	api.AssertIsEqual(a.Bitcoin, b.Bitcoin)
	api.AssertIsEqual(a.Ethereum, b.Ethereum)
}

func (circuit *Circuit) Define(api frontend.API) error {
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
