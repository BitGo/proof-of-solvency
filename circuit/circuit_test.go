package circuit

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

// SETUP --------------------------------------------------------
// Number of accounts to test with.
const NUM_ACCOUNTS = 16

// Return a circuit with empty accounts and all-zero asset sum.
func initBaseCircuit(count int) *Circuit {
	emptyAccounts := make([]Account, count)
	for i := range emptyAccounts {
		emptyAccounts[i].Balance = constructBalance()
	}

	return &Circuit{
		Accounts: emptyAccounts,
		AssetSum: constructBalance(),
	}
}

// Create base circuit to use for rest of tests
var BASE_CIRCUIT = initBaseCircuit(NUM_ACCOUNTS)

// Generate data once for all tests.
var GO_ACCOUNTS, GO_ASSET_SUM, MERKLE_ROOT, MERKLE_ROOT_WITH_ASSET_SUM_HASH = GenerateTestData(NUM_ACCOUNTS, 0)

// TESTS --------------------------------------------------------
func TestCircuitWorks(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		BASE_CIRCUIT,
		&Circuit{
			Accounts:                   ConvertGoAccountsToAccounts(GO_ACCOUNTS),
			AssetSum:                   ConvertGoBalanceToBalance(GO_ASSET_SUM),
			MerkleRoot:                 MERKLE_ROOT,
			MerkleRootWithAssetSumHash: MERKLE_ROOT_WITH_ASSET_SUM_HASH,
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestCircuitDoesNotAcceptAccountsWithOverflow(t *testing.T) {
	assert := test.NewAssert(t)

	// create a balance with 136 bits, violating range constraint
	overflowBalance := make([]byte, 17)
	for b := range overflowBalance {
		overflowBalance[b] = 0xFF
	}

	// create account with overflow balance, based on first generated go account
	badBalanceAccount := GoAccount{
		UserId:  GO_ACCOUNTS[0].UserId,
		Balance: append(GO_ACCOUNTS[0].Balance[1:], new(big.Int).SetBytes(overflowBalance)),
	}

	// add account with rest of generated accounts (remove first and add bad one to end)
	// and generate merkle root and asset sum for these
	badGoAccounts := append(GO_ACCOUNTS[1:], badBalanceAccount)
	goAssetSum := SumGoAccountBalances(badGoAccounts)
	merkleRoot := GoComputeMerkleRootFromAccounts(badGoAccounts)

	// assert failure
	assert.ProverFailed(
		BASE_CIRCUIT,
		&Circuit{
			Accounts:                   ConvertGoAccountsToAccounts(badGoAccounts),
			AssetSum:                   ConvertGoBalanceToBalance(goAssetSum),
			MerkleRoot:                 merkleRoot,
			MerkleRootWithAssetSumHash: GoComputeMiMCHashForAccount(GoAccount{merkleRoot, goAssetSum}),
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestCircuitDoesNotAcceptIncorrectAssetSum(t *testing.T) {
	assert := test.NewAssert(t)

	// add 1 to first balance to get an incorrect asset sum
	incorrectFirstBalance := new(big.Int).Add(GO_ASSET_SUM[0], big.NewInt(1))
	badAssetSum := append(GoBalance{incorrectFirstBalance}, GO_ASSET_SUM[1:]...)

	assert.ProverFailed(
		BASE_CIRCUIT,
		&Circuit{
			Accounts:                   ConvertGoAccountsToAccounts(GO_ACCOUNTS),
			AssetSum:                   ConvertGoBalanceToBalance(badAssetSum),
			MerkleRoot:                 MERKLE_ROOT,
			MerkleRootWithAssetSumHash: MERKLE_ROOT_WITH_ASSET_SUM_HASH,
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestCircuitDoesNotAcceptInvalidMerkleRoot(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverFailed(
		BASE_CIRCUIT,
		&Circuit{
			Accounts:                   ConvertGoAccountsToAccounts(GO_ACCOUNTS),
			AssetSum:                   ConvertGoBalanceToBalance(GO_ASSET_SUM),
			MerkleRoot:                 18724,
			MerkleRootWithAssetSumHash: MERKLE_ROOT_WITH_ASSET_SUM_HASH,
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}

func TestCircuitDoesNotAcceptInvalidMerkleRootWithSumHash(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverFailed(
		BASE_CIRCUIT,
		&Circuit{
			Accounts:                   ConvertGoAccountsToAccounts(GO_ACCOUNTS),
			AssetSum:                   ConvertGoBalanceToBalance(GO_ASSET_SUM),
			MerkleRoot:                 MERKLE_ROOT,
			MerkleRootWithAssetSumHash: 18724,
		},
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
	)
}
