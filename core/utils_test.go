package core

import (
	"bytes"
	"math/big"
	"os"
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

// Helper to cleanup files after test
func cleanupFiles(paths ...string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

func TestReadDataFromFile(t *testing.T) {
	t.Run("Reading ProofElements from RawProofElements file", func(t *testing.T) {

		// Create RawProofElements and write to file
		filePath := "testutildata/test_proof_elements_0.json"
		raw := createTestRawProofElements()
		err := writeJson(filePath, raw)
		if err != nil {
			panic(err)
		}
		defer cleanupFiles(filePath)

		// Read ProofElements from file (should convert from raw)
		result := ReadDataFromFile[ProofElements](filePath)

		// Verify it's properly converted
		if len(result.Accounts) != 2 {
			t.Errorf("Expected 2 accounts, got %d", len(result.Accounts))
		}

		// Verify account conversions - check UserId by converting raw accounts
		for i := 0; i < 2; i++ {
			if !bytes.Equal(result.Accounts[i].UserId, circuit.ConvertRawGoAccountToGoAccount(raw.Accounts[i]).UserId) {
				t.Errorf("UserId for account %d not converted correctly", i)
			}
		}

		// Verify MerkleRoot and MerkleRootWithAssetSumHash
		expectedMerkleRoot := []byte{10, 11, 12, 13}
		if !bytes.Equal(result.MerkleRoot, expectedMerkleRoot) {
			t.Errorf("MerkleRoot not read correctly")
		}

		expectedMerkleRootWithAssetSumHash := []byte{20, 21, 22, 23}
		if !bytes.Equal(result.MerkleRootWithAssetSumHash, expectedMerkleRootWithAssetSumHash) {
			t.Errorf("MerkleRootWithAssetSumHash not read correctly")
		}

		// Verify AssetSum
		if result.AssetSum == nil {
			t.Errorf("AssetSum should not be nil")
		} else if (*result.AssetSum)[0].Cmp(big.NewInt(400)) != 0 ||
			(*result.AssetSum)[1].Cmp(big.NewInt(600)) != 0 {
			t.Errorf("AssetSum not read correctly")
		}
	})

	t.Run("Reading CompletedProof", func(t *testing.T) {
		filePath := "testutildata/test_completed_proof_0.json"

		// Create RawCompletedProof and write to file
		original := RawCompletedProof{
			Proof:                      "AAAA",
			VerificationKey:            "BBBB",
			MerklePath:                 []Hash{{1, 2, 3, 4}, {5, 6, 7, 8}},
			MerkleNodes:                [][]Hash{{{1, 2, 3, 4}, {5, 6, 7, 8}}},
			MerkleRoot:                 []byte{10, 11, 12, 13},
			MerkleRootWithAssetSumHash: []byte{20, 21, 22, 23},
			AssetSum:                   &[]string{"400", "600"},
		}
		err := writeJson(filePath, original)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
		defer cleanupFiles(filePath)

		// Read CompletedProof from file
		result := ReadDataFromFile[CompletedProof](filePath)

		// Verify it's properly read
		if result.Proof != "AAAA" || result.VerificationKey != "BBBB" {
			t.Errorf("Proof or VerificationKey not read correctly")
		}

		// Verify MerklePath
		if len(result.MerklePath) != 2 {
			t.Errorf("Expected 2 in MerklePath, got %d", len(result.MerklePath))
		}

		// Verify first MerklePath hash
		expectedHash1 := Hash{1, 2, 3, 4}
		if !bytes.Equal(result.MerklePath[0], expectedHash1) {
			t.Errorf("First MerklePath hash not read correctly")
		}

		// Verify MerkleNodes
		if len(result.MerkleNodes) != 1 {
			t.Errorf("Expected 1 level in MerkleNodes, got %d", len(result.MerkleNodes))
		}

		// Verify MerkleRoot and MerkleRootWithAssetSumHash
		expectedMerkleRoot := []byte{10, 11, 12, 13}
		if !bytes.Equal(result.MerkleRoot, expectedMerkleRoot) {
			t.Errorf("MerkleRoot not read correctly")
		}

		expectedMerkleRootWithAssetSumHash := []byte{20, 21, 22, 23}
		if !bytes.Equal(result.MerkleRootWithAssetSumHash, expectedMerkleRootWithAssetSumHash) {
			t.Errorf("MerkleRootWithAssetSumHash not read correctly")
		}

		// Verify AssetSum
		if result.AssetSum == nil {
			t.Errorf("AssetSum should not be nil")
		}
		if len(*result.AssetSum) != 2 {
			t.Errorf("Expected AssetSum length 2, got %d", len(*result.AssetSum))
		}
		if (*result.AssetSum)[0].Int64() != 400 || (*result.AssetSum)[1].Int64() != 600 {
			t.Errorf("AssetSum values not read correctly: expected [400, 600], got %v", *result.AssetSum)
		}
	})

	t.Run("Reading CompletedProof with nil AssetSum", func(t *testing.T) {
		filePath := "testutildata/test_completed_proof_0.json"

		// Create RawCompletedProof and write to file
		original := RawCompletedProof{
			Proof:                      "AAAA",
			VerificationKey:            "BBBB",
			MerklePath:                 []Hash{{1, 2, 3, 4}, {5, 6, 7, 8}},
			MerkleNodes:                [][]Hash{{{1, 2, 3, 4}, {5, 6, 7, 8}}},
			MerkleRoot:                 []byte{10, 11, 12, 13},
			MerkleRootWithAssetSumHash: []byte{20, 21, 22, 23},
			AssetSum:                   nil,
		}
		err := writeJson(filePath, original)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
		defer cleanupFiles(filePath)

		// Read CompletedProof from file
		result := ReadDataFromFile[CompletedProof](filePath)

		// Verify it's properly read
		if result.Proof != "AAAA" || result.VerificationKey != "BBBB" {
			t.Errorf("Proof or VerificationKey not read correctly")
		}

		// Verify MerklePath
		if len(result.MerklePath) != 2 {
			t.Errorf("Expected 2 in MerklePath, got %d", len(result.MerklePath))
		}

		// Verify first MerklePath hash
		expectedHash1 := Hash{1, 2, 3, 4}
		if !bytes.Equal(result.MerklePath[0], expectedHash1) {
			t.Errorf("First MerklePath hash not read correctly")
		}

		// Verify MerkleNodes
		if len(result.MerkleNodes) != 1 {
			t.Errorf("Expected 1 level in MerkleNodes, got %d", len(result.MerkleNodes))
		}

		// Verify MerkleRoot and MerkleRootWithAssetSumHash
		expectedMerkleRoot := []byte{10, 11, 12, 13}
		if !bytes.Equal(result.MerkleRoot, expectedMerkleRoot) {
			t.Errorf("MerkleRoot not read correctly")
		}

		expectedMerkleRootWithAssetSumHash := []byte{20, 21, 22, 23}
		if !bytes.Equal(result.MerkleRootWithAssetSumHash, expectedMerkleRootWithAssetSumHash) {
			t.Errorf("MerkleRootWithAssetSumHash not read correctly")
		}

		// Verify AssetSum
		if result.AssetSum != nil {
			t.Errorf("AssetSum should be nil")
		}
	})

	t.Run("Reading GoAccount from RawGoAccount file", func(t *testing.T) {
		filePath := "testutildata/test_account_0.json"
		// Create RawGoAccount and write to file directly with writeJson
		rawAccount := circuit.RawGoAccount{
			UserId:  "test-account-123",
			Balance: circuit.ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
		}
		err := writeJson(filePath, rawAccount)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
		defer cleanupFiles(filePath)

		// Read GoAccount from file (should convert from raw)
		result := ReadDataFromFile[circuit.GoAccount](filePath)

		// Verify it's properly converted from RawGoAccount
		expectedAccount := circuit.ConvertRawGoAccountToGoAccount(rawAccount)

		// Verify UserID was properly converted
		if !bytes.Equal(result.UserId, expectedAccount.UserId) {
			t.Errorf("UserId not converted correctly: expected %v, got %v",
				expectedAccount.UserId, result.UserId)
		}

		// Verify balance
		if result.Balance[0].Cmp(big.NewInt(100)) != 0 ||
			result.Balance[1].Cmp(big.NewInt(200)) != 0 {
			t.Errorf("Balance not read correctly")
		}
	})

	t.Run("Reading UserVerificationElements from raw file", func(t *testing.T) {
		filePath := "testutildata/test_user_verification_0.json"

		// Create raw user verification elements
		rawUserElements := RawUserVerificationElements{
			AccountInfo: circuit.RawGoAccount{
				UserId:  "test-user-abc",
				Balance: circuit.ConstructGoBalance(big.NewInt(500), big.NewInt(700)),
			},
			ProofInfo: RawUserProofInfo{
				UserMerklePath:     []Hash{{1, 2, 3}, {4, 5, 6}},
				UserMerklePosition: 42,
				BottomProof: RawLowerLevelProof{
					Proof:                      "BottomProof",
					VerificationKey:            "BottomVK",
					MerkleRoot:                 []byte{1, 2, 3},
					MerkleRootWithAssetSumHash: []byte{4, 5, 6},
					MerklePath:                 []Hash{{7, 8, 9}, {10, 11, 12}},
					MerklePosition:             123,
				},
				MiddleProof: RawLowerLevelProof{
					Proof:                      "MiddleProof",
					VerificationKey:            "MiddleVK",
					MerkleRoot:                 []byte{13, 14, 15},
					MerkleRootWithAssetSumHash: []byte{16, 17, 18},
					MerklePath:                 []Hash{{19, 20, 21}, {22, 23, 24}},
					MerklePosition:             456,
				},
				TopProof: RawTopLevelProof{
					Proof:                      "TopProof",
					VerificationKey:            "TopVK",
					MerkleRoot:                 []byte{25, 26, 27},
					MerkleRootWithAssetSumHash: []byte{28, 29, 30},
					AssetSum:                   &[]string{"1000", "2000"},
				},
			},
		}

		err := writeJson(filePath, rawUserElements)
		if err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
		defer cleanupFiles(filePath)

		// Read UserVerificationElements from file
		result := ReadDataFromFile[UserVerificationElements](filePath)

		// Verify AccountInfo
		expectedAccount := circuit.ConvertRawGoAccountToGoAccount(rawUserElements.AccountInfo)
		if !bytes.Equal(result.AccountInfo.UserId, expectedAccount.UserId) {
			t.Errorf("UserId not converted correctly: expected %v, got %v",
				expectedAccount.UserId, result.AccountInfo.UserId)
		}
		if result.AccountInfo.Balance[0].Cmp(big.NewInt(500)) != 0 ||
			result.AccountInfo.Balance[1].Cmp(big.NewInt(700)) != 0 {
			t.Errorf("AccountInfo Balance not read correctly")
		}

		// Verify UserMerklePath and Position
		if len(result.ProofInfo.UserMerklePath) != 2 {
			t.Errorf("Expected 2 in UserMerklePath, got %d", len(result.ProofInfo.UserMerklePath))
		}
		if result.ProofInfo.UserMerklePosition != 42 {
			t.Errorf("UserMerklePosition not read correctly: expected 42, got %d", result.ProofInfo.UserMerklePosition)
		}

		// Verify BottomProof
		if result.ProofInfo.BottomProof.Proof != "BottomProof" || result.ProofInfo.BottomProof.VerificationKey != "BottomVK" {
			t.Errorf("BottomProof Proof or VK not read correctly")
		}
		if !bytes.Equal(result.ProofInfo.BottomProof.MerkleRoot, []byte{1, 2, 3}) {
			t.Errorf("BottomProof MerkleRoot not read correctly")
		}
		if result.ProofInfo.BottomProof.MerklePosition != 123 {
			t.Errorf("BottomProof MerklePosition not read correctly")
		}

		// Verify MiddleProof
		if result.ProofInfo.MiddleProof.Proof != "MiddleProof" || result.ProofInfo.MiddleProof.VerificationKey != "MiddleVK" {
			t.Errorf("MiddleProof Proof or VK not read correctly")
		}
		if !bytes.Equal(result.ProofInfo.MiddleProof.MerkleRoot, []byte{13, 14, 15}) {
			t.Errorf("MiddleProof MerkleRoot not read correctly")
		}
		if result.ProofInfo.MiddleProof.MerklePosition != 456 {
			t.Errorf("MiddleProof MerklePosition not read correctly")
		}

		// Verify TopProof
		if result.ProofInfo.TopProof.Proof != "TopProof" || result.ProofInfo.TopProof.VerificationKey != "TopVK" {
			t.Errorf("TopProof Proof or VK not read correctly")
		}
		if !bytes.Equal(result.ProofInfo.TopProof.MerkleRoot, []byte{25, 26, 27}) {
			t.Errorf("TopProof MerkleRoot not read correctly")
		}

		// Verify TopProof AssetSum
		if result.ProofInfo.TopProof.AssetSum == nil {
			t.Errorf("TopProof AssetSum should not be nil")
		}
		if len(*result.ProofInfo.TopProof.AssetSum) != 2 {
			t.Errorf("Expected TopProof AssetSum length 2, got %d", len(*result.ProofInfo.TopProof.AssetSum))
		}
		if (*result.ProofInfo.TopProof.AssetSum)[0].Cmp(big.NewInt(1000)) != 0 ||
			(*result.ProofInfo.TopProof.AssetSum)[1].Cmp(big.NewInt(2000)) != 0 {
			t.Errorf("TopProof AssetSum values not read correctly: expected [1000, 2000], got %v", *result.ProofInfo.TopProof.AssetSum)
		}
	})
}

func TestWriteReadDataRoundTrip(t *testing.T) {
	t.Run("Round trip ProofElements", func(t *testing.T) {
		// Create test data
		original := createTestProofElements()
		filePath := "testutildata/test_write_proof_elements.json"

		// Write to file
		WriteDataToFile(filePath, original)
		defer cleanupFiles(filePath)

		// Read back from file
		result := ReadDataFromFile[ProofElements](filePath)

		// Verify accounts count matches
		if len(result.Accounts) != len(original.Accounts) {
			t.Errorf("Expected %d accounts, got %d", len(original.Accounts), len(result.Accounts))
		}

		// Verify account hashes match
		for i, originalAccount := range original.Accounts {
			resultAccount := result.Accounts[i]

			// Check hashes
			originalHash := circuit.GoComputeMiMCHashForAccount(originalAccount)
			resultHash := circuit.GoComputeMiMCHashForAccount(resultAccount)

			if !bytes.Equal(originalHash, resultHash) {
				t.Errorf("Account #%d hash doesn't match after round-trip", i)
			}

			// Check balances match
			if !resultAccount.Balance.Equals(originalAccount.Balance) {
				t.Errorf("Account #%d balance doesn't match after round-trip", i)
			}
		}

		// Verify MerkleRoot preserved
		if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
			t.Errorf("MerkleRoot not preserved in round-trip")
		}

		// Verify MerkleRootWithAssetSumHash preserved
		if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
			t.Errorf("MerkleRootWithAssetSumHash not preserved in round-trip")
		}

		// Verify AssetSum values match
		for i := 0; i < 2; i++ { // Check first two values which we know are non-zero
			if (*result.AssetSum)[i].Cmp((*original.AssetSum)[i]) != 0 {
				t.Errorf("AssetSum[%d] doesn't match after round-trip", i)
			}
		}
	})

	t.Run("Round trip CompletedProof", func(t *testing.T) {
		// Create test data
		original := CompletedProof{
			Proof:                      "TestProof",
			VerificationKey:            "TestVK",
			MerklePath:                 []Hash{{1, 2, 3}, {4, 5, 6}},
			MerkleNodes:                [][]Hash{{{1, 2, 3}, {4, 5, 6}}},
			MerkleRoot:                 []byte{10, 11, 12},
			MerkleRootWithAssetSumHash: []byte{20, 21, 22},
			AssetSum:                   createTestProofElements().AssetSum,
		}
		filePath := "testutildata/test_write_completed_proof.json"

		// Write to file
		WriteDataToFile(filePath, original)
		defer cleanupFiles(filePath)

		// Read back from file
		result := ReadDataFromFile[CompletedProof](filePath)

		// Verify fields match
		if result.Proof != original.Proof || result.VerificationKey != original.VerificationKey {
			t.Errorf("Proof or VK doesn't match after round-trip")
		}

		// Verify MerklePath match
		if len(result.MerklePath) != len(original.MerklePath) {
			t.Errorf("MerklePath length doesn't match after round-trip")
		} else {
			for i, originalPath := range original.MerklePath {
				if !bytes.Equal(result.MerklePath[i], originalPath) {
					t.Errorf("MerklePath #%d doesn't match after round-trip", i)
				}
			}
		}

		// Verify MerkleNodes match
		if len(result.MerkleNodes) != len(original.MerkleNodes) {
			t.Errorf("MerkleNodes length doesn't match after round-trip")
		}

		// Verify MerkleRoot and MerkleRootWithAssetSumHash
		if !bytes.Equal(result.MerkleRoot, original.MerkleRoot) {
			t.Errorf("MerkleRoot doesn't match after round-trip")
		}
		if !bytes.Equal(result.MerkleRootWithAssetSumHash, original.MerkleRootWithAssetSumHash) {
			t.Errorf("MerkleRootWithAssetSumHash doesn't match after round-trip")
		}

		// Verify AssetSum values match
		for i := 0; i < 2; i++ { // Check first two values which we know are non-zero
			if (*result.AssetSum)[i].Cmp((*original.AssetSum)[i]) != 0 {
				t.Errorf("AssetSum[%d] doesn't match after round-trip", i)
			}
		}
	})

	t.Run("Round trip GoAccount", func(t *testing.T) {
		// Create test data
		rawAccount := circuit.RawGoAccount{
			UserId:  "test-account-xyz",
			Balance: circuit.ConstructGoBalance(big.NewInt(123), big.NewInt(456)),
		}
		original := circuit.ConvertRawGoAccountToGoAccount(rawAccount)
		filePath := "testutildata/test_write_account.json"

		// Write to file
		WriteDataToFile(filePath, original)
		defer cleanupFiles(filePath)

		// Read back from file
		result := ReadDataFromFile[circuit.GoAccount](filePath)

		// Verify account hash matches (since UserId byte representation might differ due to conversion)
		originalHash := circuit.GoComputeMiMCHashForAccount(original)
		resultHash := circuit.GoComputeMiMCHashForAccount(result)
		if !bytes.Equal(originalHash, resultHash) {
			t.Errorf("Account hash doesn't match after round-trip")
		}

		// Verify balance
		if !result.Balance.Equals(original.Balance) {
			t.Errorf("Balance doesn't match after round-trip")
		}
	})
}
