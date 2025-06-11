package core

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark/test"
)

func TestBatchProofs(t *testing.T) {
	assert := test.NewAssert(t)

	// we make completed proofs here
	proofs1 := make([]CompletedProof, 0)
	proofs2 := make([]CompletedProof, 16)
	proofs3 := make([]CompletedProof, 17)
	proofs4 := make([]CompletedProof, 32)
	proofs5 := make([]CompletedProof, 16000)

	assert.Equal(0, len(batchProofs(proofs1, 16)))
	assert.Equal(1, len(batchProofs(proofs2, 16)))
	assert.Equal(2, len(batchProofs(proofs3, 16)))
	assert.Equal(2, len(batchProofs(proofs4, 16)))
	assert.Equal(1000, len(batchProofs(proofs5, 16)))
	assert.Panics(func() { batchProofs(proofs3, 0) })
}

func createTestProofElements() ProofElements {
	// Create sample accounts
	accounts := []circuit.GoAccount{
		{
			UserId:  []byte{1, 2, 3},
			Balance: circuit.ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
		},
		{
			UserId:  []byte{4, 5, 6},
			Balance: circuit.ConstructGoBalance(big.NewInt(300), big.NewInt(400)),
		},
	}

	// Sum balances for test data
	assetSum := circuit.SumGoAccountBalances(accounts)

	// Create merkle root and hash
	merkleRoot := []byte{10, 11, 12, 13}
	merkleRootWithAssetSumHash := []byte{20, 21, 22, 23}

	return ProofElements{
		Accounts:                   accounts,
		AssetSum:                   &assetSum,
		MerkleRoot:                 merkleRoot,
		MerkleRootWithAssetSumHash: merkleRootWithAssetSumHash,
	}
}

func createTestRawProofElements() RawProofElements {
	// Create sample accounts
	accounts := []circuit.RawGoAccount{
		{
			UserId:  "user1",
			Balance: circuit.ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
		},
		{
			UserId:  "user2",
			Balance: circuit.ConstructGoBalance(big.NewInt(300), big.NewInt(400)),
		},
	}

	// Sum balances for test data
	converted := circuit.ConvertRawGoAccountsToGoAccounts(accounts)
	assetSum := circuit.SumGoAccountBalances(converted)

	// Create merkle root and hash
	merkleRoot := []byte{10, 11, 12, 13}
	merkleRootWithAssetSumHash := []byte{20, 21, 22, 23}

	return RawProofElements{
		Accounts:                   accounts,
		AssetSum:                   &assetSum,
		MerkleRoot:                 merkleRoot,
		MerkleRootWithAssetSumHash: merkleRootWithAssetSumHash,
	}
}

func TestConvertProofElementsToRawProofElements(t *testing.T) {
	// Create test ProofElements
	original := createTestProofElements()

	// Convert to RawProofElements
	result := ConvertProofElementsToRawProofElements(original)

	// Verify accounts have been correctly converted
	if len(result.Accounts) != len(original.Accounts) {
		t.Errorf("Expected %d accounts, got %d", len(original.Accounts), len(result.Accounts))
	}

	// Verify account conversion by checking a sample
	// Convert back to bytes for comparison
	convertedUserId := circuit.ConvertRawGoAccountToGoAccount(result.Accounts[0]).UserId
	if !bytes.Equal(convertedUserId, original.Accounts[0].UserId) {
		t.Errorf("UserId not converted correctly. Expected %v, got %v after reconversion",
			original.Accounts[0].UserId, convertedUserId)
	}

	// Verify AssetSum is preserved (same pointer)
	if result.AssetSum != original.AssetSum {
		t.Errorf("AssetSum pointer not preserved")
	}

	// Verify MerkleRoot is preserved
	if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
		t.Errorf("MerkleRoot not preserved")
	}

	// Verify MerkleRootWithAssetSumHash is preserved
	if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
		t.Errorf("MerkleRootWithAssetSumHash not preserved")
	}
}

func TestConvertRawProofElementsToProofElements(t *testing.T) {
	// Create test RawProofElements
	original := createTestRawProofElements()

	// Convert to ProofElements
	result := ConvertRawProofElementsToProofElements(original)

	// Verify accounts have been correctly converted
	if len(result.Accounts) != len(original.Accounts) {
		t.Errorf("Expected %d accounts, got %d", len(original.Accounts), len(result.Accounts))
	}

	// Verify account conversion by checking a sample
	// Original raw account
	rawAccount := original.Accounts[0]

	// Converted account
	convertedAccount := result.Accounts[0]

	// Manually convert raw account to verify
	expectedAccount := circuit.ConvertRawGoAccountToGoAccount(rawAccount)

	// Compare converted UserIds
	if !bytes.Equal(convertedAccount.UserId, expectedAccount.UserId) {
		t.Errorf("UserId not converted correctly")
	}

	// Compare balances
	if !convertedAccount.Balance.Equals(expectedAccount.Balance) {
		t.Errorf("Balance not converted correctly")
	}

	// Verify AssetSum is preserved (same pointer)
	if result.AssetSum != original.AssetSum {
		t.Errorf("AssetSum pointer not preserved")
	}

	// Verify MerkleRoot is preserved
	if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
		t.Errorf("MerkleRoot not preserved")
	}

	// Verify MerkleRootWithAssetSumHash is preserved
	if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
		t.Errorf("MerkleRootWithAssetSumHash not preserved")
	}
}

func TestRoundTripProofElementsToRaw(t *testing.T) {
	// Create test ProofElements
	original := createTestProofElements()

	// Convert to RawProofElements and back
	raw := ConvertProofElementsToRawProofElements(original)
	result := ConvertRawProofElementsToProofElements(raw)

	// Verify accounts have been correctly round-tripped
	if len(result.Accounts) != len(original.Accounts) {
		t.Errorf("Expected %d accounts, got %d", len(original.Accounts), len(result.Accounts))
	}

	// Verify account conversion for each account
	for i, originalAccount := range original.Accounts {
		resultAccount := result.Accounts[i]

		// UserId may be different due to base36 conversion and back, but should be functionally equivalent
		// Original UserId -> RawUserId (base36) -> UserId could produce different byte representation
		// but with equivalent numerical value

		// Instead, test with account hashing which is what matters functionally
		originalHash := circuit.GoComputeMiMCHashForAccount(originalAccount)
		resultHash := circuit.GoComputeMiMCHashForAccount(resultAccount)

		if !bytes.Equal(originalHash, resultHash) {
			t.Errorf("Account #%d hash doesn't match after round-trip", i)
		}

		// Balances should remain the same
		if !resultAccount.Balance.Equals(originalAccount.Balance) {
			t.Errorf("Account #%d balance doesn't match after round-trip", i)
		}
	}

	// Verify AssetSum is preserved
	if !reflect.DeepEqual(result.AssetSum, original.AssetSum) {
		t.Errorf("AssetSum not preserved in round-trip")
	}

	// Verify MerkleRoot is preserved
	if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
		t.Errorf("MerkleRoot not preserved in round-trip")
	}

	// Verify MerkleRootWithAssetSumHash is preserved
	if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
		t.Errorf("MerkleRootWithAssetSumHash not preserved in round-trip")
	}
}

func TestRoundTripRawToProofElements(t *testing.T) {
	// Create test RawProofElements
	original := createTestRawProofElements()

	// Convert to ProofElements and back
	proof := ConvertRawProofElementsToProofElements(original)
	result := ConvertProofElementsToRawProofElements(proof)

	// Verify accounts have been correctly round-tripped
	if len(result.Accounts) != len(original.Accounts) {
		t.Errorf("Expected %d accounts, got %d", len(original.Accounts), len(result.Accounts))
	}

	// Verify UserIds - these may have changed format but should be functionally equivalent
	// Check that each userId in the result can be converted to a byte representation that
	// when hashed produces the same hash as the original userId
	for i, originalAccount := range original.Accounts {
		resultAccount := result.Accounts[i]

		// Convert both to GoAccounts for comparison
		originalGo := circuit.ConvertRawGoAccountToGoAccount(originalAccount)
		resultGo := circuit.ConvertRawGoAccountToGoAccount(resultAccount)

		// Check account hashing
		originalHash := circuit.GoComputeMiMCHashForAccount(originalGo)
		resultHash := circuit.GoComputeMiMCHashForAccount(resultGo)

		if !bytes.Equal(originalHash, resultHash) {
			t.Errorf("Account #%d hash doesn't match after round-trip", i)
		}

		// Balances should remain the same
		if !resultAccount.Balance.Equals(originalAccount.Balance) {
			t.Errorf("Account #%d balance doesn't match after round-trip", i)
		}
	}

	// Verify AssetSum is preserved
	if !reflect.DeepEqual(result.AssetSum, original.AssetSum) {
		t.Errorf("AssetSum not preserved in round-trip")
	}

	// Verify MerkleRoot is preserved
	if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
		t.Errorf("MerkleRoot not preserved in round-trip")
	}

	// Verify MerkleRootWithAssetSumHash is preserved
	if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
		t.Errorf("MerkleRootWithAssetSumHash not preserved in round-trip")
	}
}
