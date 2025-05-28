package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const count = 16

var baseCircuit = initBaseCircuit(count)

func initBaseCircuit(count int) *Circuit {
	// create a circuit with empty accounts and all-zero asset sum
	emptyAccounts := make([]Account, count)
	for i := range emptyAccounts {
		zeroBalances := make([]frontend.Variable, GetNumberOfAssets())
		for j := range zeroBalances {
			zeroBalances[j] = frontend.Variable(0)
		}
		emptyAccounts[i].Balance = zeroBalances
	}
	emptySum := make(Balance, GetNumberOfAssets())
	for i := range emptySum {
		emptySum[i] = frontend.Variable(0)
	}

	return &Circuit{
		Accounts: emptyAccounts,
		AssetSum: emptySum,
	}
}

func TestCircuitWorks(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, goAssetSum, goMerkleRoot, goMerkleRootWithHash := GenerateTestData(count, 0) // Generate test data for 128 accounts
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	c.MerkleRoot = goMerkleRoot
	c.MerkleRootWithAssetSumHash = goMerkleRootWithHash

	assert.ProverSucceeded(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCircuitDoesNotAcceptAccountsWithOverflow(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, _, _, _ := GenerateTestData(count, 0)
	amt := make([]byte, 9) // this is 72 bits, overflowing our rangecheck
	for b := range amt {
		amt[b] = 0xFF
	}
	goAccounts[0].Balance[0] = new(big.Int).SetBytes(amt)
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	goAssetSum := SumGoAccountBalances(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	merkleRoot := GoComputeMerkleRootFromAccounts(goAccounts)
	c.MerkleRoot = merkleRoot
	c.MerkleRootWithAssetSumHash = GoComputeMiMCHashForAccount(GoAccount{merkleRoot, goAssetSum})

	assert.ProverFailed(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCircuitDoesNotAcceptInvalidMerkleRoot(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, goAssetSum, _, goMerkleRootWithHash := GenerateTestData(count, 0) // Generate test data for 128 accounts
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	c.MerkleRoot = 123
	c.MerkleRootWithAssetSumHash = goMerkleRootWithHash

	assert.ProverFailed(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCircuitDoesNotAcceptInvalidMerkleRootWithSumHash(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, goAssetSum, merkleRoot, _ := GenerateTestData(count, 0) // Generate test data for 128 accounts
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	c.MerkleRoot = merkleRoot
	c.MerkleRootWithAssetSumHash = 123

	assert.ProverFailed(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
