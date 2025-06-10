package circuit

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// Instead of implementing a mock API, let's modify our approach

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

// MAIN TESTS --------------------------------------------------------
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

// UTIL TESTS ------------------------------------------------------
func TestPowOfTwo(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{0, 1},
		{1, 2},
		{4, 16},
		{10, 1024},
	}
	for _, tc := range tests {
		result := powOfTwo(tc.input)
		if result != tc.expected {
			t.Errorf("powOfTwo(%d) = %d; expected %d", tc.input, result, tc.expected)
		}
	}
}

// PANIC TESTS ----------------------------------------------
func TestCircuitPanicsOnAccountWithWrongBalanceLength(t *testing.T) {
	assetSum := ConvertGoBalanceToBalance(GO_ASSET_SUM)

	// two testcases: one with an account with balance less than required length, and
	// one with balance greater than required length
	tests := []Circuit{
		{
			Accounts: func() []Account {
				// corrupt first account with a balance greater than required length
				accounts := ConvertGoAccountsToAccounts(GO_ACCOUNTS)
				accounts[0].Balance = append(accounts[0].Balance, frontend.Variable(0))
				return accounts

			}(),
			AssetSum:                   assetSum,
			MerkleRoot:                 MERKLE_ROOT,
			MerkleRootWithAssetSumHash: MERKLE_ROOT_WITH_ASSET_SUM_HASH,
		},
		{
			Accounts: func() []Account {
				// corrupt first account with a balance less than required length
				accounts := ConvertGoAccountsToAccounts(GO_ACCOUNTS)
				accounts[0].Balance = accounts[0].Balance[0 : GetNumberOfAssets()-1]
				return accounts

			}(),
			AssetSum:                   assetSum,
			MerkleRoot:                 MERKLE_ROOT,
			MerkleRootWithAssetSumHash: MERKLE_ROOT_WITH_ASSET_SUM_HASH,
		},
	}

	for i, c := range tests {
		err := test.IsSolved(&c, &c, ecc.BN254.ScalarField())
		if err == nil {
			t.Errorf("Test %d: Expected error 'balances must have the same length as assets' but there was no error.", i)
		}

		if message := strings.Split(err.Error(), "\n")[0]; message != "balances must have the same length as assets" {
			t.Errorf("Test %d: Expected error with message 'balances must have the same length as assets', got: %v", i, message)
		}
	}

}

func TestCircuitPanicsWhenTooManyAccounts(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic, but did not panic")
		} else if msg, ok := r.(string); !ok || msg != "number of accounts exceeds the maximum number of leaves in the Merkle tree" {
			t.Errorf("Expected panic with message 'number of accounts exceeds the maximum number of leaves in the Merkle tree', got: %v", r)
		}
	}()
	tooMany := powOfTwo(TreeDepth) + 1
	accounts := make([]Account, tooMany)
	for i := range accounts {
		accounts[i].Balance = constructBalance()
	}

	badCircuit := &Circuit{
		Accounts: accounts,
		AssetSum: constructBalance(),
	}

	// Just accessing the Define method with this circuit should trigger the panic
	badCircuit.Define(nil)
}
