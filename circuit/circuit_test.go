package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

const count = 16

var baseCircuit = initBaseCircuit(count)

func initBaseCircuit(count int) *Circuit {
	return &Circuit{
		Accounts: make([]Account, count),
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

func TestCircuitDoesNotAcceptNegativeAccounts(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, _, _, _ := GenerateTestData(count, 0)
	goAccounts[0].Balance.Bitcoin = *big.NewInt(-1)
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	goAssetSum := SumGoAccountBalancesIncludingNegatives(goAccounts)
	c.AssetSum = ConvertGoBalanceToBalance(goAssetSum)
	merkleRoot := GoComputeMerkleRootFromAccounts(goAccounts)
	c.MerkleRoot = merkleRoot
	c.MerkleRootWithAssetSumHash = GoComputeMiMCHashForAccount(GoAccount{merkleRoot, goAssetSum})

	assert.ProverFailed(baseCircuit, &c, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCircuitDoesNotAcceptAccountsWithOverflow(t *testing.T) {
	assert := test.NewAssert(t)

	var c Circuit
	goAccounts, _, _, _ := GenerateTestData(count, 0)
	amt := make([]byte, 9) // this is 72 bits, overflowing our rangecheck
	for b := range amt {
		amt[b] = 0xFF
	}
	goAccounts[0].Balance.Bitcoin = *new(big.Int).SetBytes(amt)
	c.Accounts = ConvertGoAccountsToAccounts(goAccounts)
	goAssetSum := SumGoAccountBalancesIncludingNegatives(goAccounts)
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
