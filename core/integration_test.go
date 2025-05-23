package core

import (
	"bytes"
	"math/big"
	"os"
	"strconv"
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
)

// testing constants:
const batchCount = 2
const countPerBatch = 16

// TestMain sets up the test environment by generating test data and proofs once
// for all tests to use.
func TestMain(m *testing.M) {
	// Clean up output directory before running tests
	os.RemoveAll("out")
	os.MkdirAll("out/secret", 0755)
	os.MkdirAll("out/public", 0755)
	os.MkdirAll("out/user", 0755)

	// Generate test data with 5 batches of 16 accounts each
	GenerateData(batchCount, countPerBatch)

	// Generate proofs for the test data
	Prove(batchCount)

	// Run tests
	exitCode := m.Run()

	// Exit with test status code
	os.Exit(exitCode)
}

// TestVerifyRandomAccount tests that random accounts cannot be verified
func TestVerifyRandomAccount(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected verifying random account to panic, but it didn't")
		}
	}()

	randomAccount := circuit.GoAccount{
		UserId: []byte("random_user_id"),
		Balance: circuit.GoBalance{
			Bitcoin:  *big.NewInt(123456),
			Ethereum: *big.NewInt(654321),
		},
	}

	// This should panic because the random account's hash is not in any of the proofs
	Verify(batchCount, randomAccount)
}

// TestVerifyModifiedBalance tests that accounts with valid userId but modified balance cannot be verified
func TestVerifyModifiedBalance(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected verifying modified account to panic, but it didn't")
		}
	}()

	// Read a valid account
	validAccount := ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")

	// Modify one balance field
	modifiedAccount := validAccount
	modifiedAccount.Balance.Bitcoin = *big.NewInt(999999) // Different BTC balance

	// This should panic because the modified account's hash doesn't match what's in the proof
	Verify(batchCount, modifiedAccount)
}

// TestVerifyValidAccount tests that valid accounts included in the proofs can be verified
func TestVerifyValidAccount(t *testing.T) {
	// Get a valid account (the test account created during GenerateData)
	validAccount := ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")

	// This should not panic
	Verify(batchCount, validAccount)
}

// TestVerifyAllAccounts iterates through all batches to verify every account
func TestVerifyAllAccounts(t *testing.T) {
	// Read all batch data files
	batches := ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")

	// Verify each account in each batch
	for batchIdx, batch := range batches {
		for accountIdx, account := range batch.Accounts {
			// Skip testing all accounts as it would be too slow, test a couple from each batch
			if accountIdx > 3 {
				continue
			}

			t.Logf("Verifying batch %d account %d", batchIdx, accountIdx)

			// This should not panic
			Verify(batchCount, account)
		}
	}
}

// findProofPathForAccount determines the appropriate bottom, mid, and top level proofs
// for a given account.
func findProofPathForAccount(account circuit.GoAccount) (bottomProofIdx, midProofIdx int) {
	batches := ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")

	accountHash := circuit.GoComputeMiMCHashForAccount(account)

	// Find which bottom level proof contains the account
	for batchIdx, batch := range batches {
		for _, batchAccount := range batch.Accounts {
			if bytes.Equal(accountHash, circuit.GoComputeMiMCHashForAccount(batchAccount)) {
				// Found the account in this batch
				return batchIdx, batchIdx / 1024
			}
		}
	}

	return -1, -1 // Account not found
}

// TestVerifyProofPathRandomAccount tests that random accounts cannot be verified with any proof path
func TestVerifyProofPathRandomAccount(t *testing.T) {
	randomAccount := circuit.GoAccount{
		UserId: []byte("random_user_id"),
		Balance: circuit.GoBalance{
			Bitcoin:  *big.NewInt(123456),
			Ethereum: *big.NewInt(654321),
		},
	}

	accountHash := circuit.GoComputeMiMCHashForAccount(randomAccount)

	// Try with all available bottom level proofs
	for i := 0; i < batchCount; i++ {
		bottomProof := ReadDataFromFile[CompletedProof]("out/public/test_proof_" + strconv.Itoa(i) + ".json")
		midProofIdx := i / 1024 // Assuming 1024 bottom proofs per mid-level proof
		midProof := ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_" + strconv.Itoa(midProofIdx) + ".json")
		topProof := ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")

		// Each verification should panic because the random account is not included in any proof
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected verifying random account with bottom proof %d to panic, but it didn't", i)
				}
			}()

			VerifyProofPath(accountHash, bottomProof, midProof, topProof)
		}()
	}
}

// TestVerifyProofPathModifiedBalance tests accounts with valid userId but modified balance
func TestVerifyProofPathModifiedBalance(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected verifying modified account to panic, but it didn't")
		}
	}()

	// Read a valid account
	validAccount := ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")

	// Find which bottom and mid level proofs this account belongs to
	bottomProofIdx, midProofIdx := findProofPathForAccount(validAccount)

	// Verify the indexes were found
	if bottomProofIdx == -1 || midProofIdx == -1 {
		t.Fatalf("Could not find proof path for valid account")
	}

	// Modify one balance field
	modifiedAccount := validAccount
	modifiedAccount.Balance.Bitcoin = *big.NewInt(999999) // Different BTC balance

	// Get the proofs for this account
	bottomProof := ReadDataFromFile[CompletedProof]("out/public/test_proof_" + strconv.Itoa(bottomProofIdx) + ".json")
	midProof := ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_" + strconv.Itoa(midProofIdx) + ".json")
	topProof := ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")

	// This should panic because the account balance is modified and hash won't match
	accountHash := circuit.GoComputeMiMCHashForAccount(modifiedAccount)
	VerifyProofPath(accountHash, bottomProof, midProof, topProof)
}

// TestVerifyProofPathValidAccount tests that valid accounts with correct proof paths can be verified
func TestVerifyProofPathValidAccount(t *testing.T) {
	// Read a valid account
	validAccount := ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")

	// Find which bottom and mid level proofs this account belongs to
	bottomProofIdx, midProofIdx := findProofPathForAccount(validAccount)

	// Verify the indexes were found
	if bottomProofIdx == -1 || midProofIdx == -1 {
		t.Fatalf("Could not find proof path for valid account")
	}

	// Get the proofs for this account
	bottomProof := ReadDataFromFile[CompletedProof]("out/public/test_proof_" + strconv.Itoa(bottomProofIdx) + ".json")
	midProof := ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_" + strconv.Itoa(midProofIdx) + ".json")
	topProof := ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")

	// This should not panic
	accountHash := circuit.GoComputeMiMCHashForAccount(validAccount)
	VerifyProofPath(accountHash, bottomProof, midProof, topProof)
}

// TestVerifyProofPathValidAccountAllAccounts tests all accounts with their correct proof paths
func TestVerifyProofPathValidAccountAllAccounts(t *testing.T) {
	batches := ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")

	// Test a few accounts from each batch
	for batchIdx, batch := range batches {
		for accountIdx, account := range batch.Accounts {
			// Skip testing all accounts as it would be too slow, test a couple from each batch
			if accountIdx > 2 {
				continue
			}

			t.Logf("Verifying proof path for batch %d account %d", batchIdx, accountIdx)

			// Get the proofs for this account
			midProofIdx := batchIdx / 1024 // Assuming 1024 bottom proofs per mid-level proof
			bottomProof := ReadDataFromFile[CompletedProof]("out/public/test_proof_" + strconv.Itoa(batchIdx) + ".json")
			midProof := ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_" + strconv.Itoa(midProofIdx) + ".json")
			topProof := ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")

			// This should not panic
			accountHash := circuit.GoComputeMiMCHashForAccount(account)
			VerifyProofPath(accountHash, bottomProof, midProof, topProof)
		}
	}
}

// TestVerifyProofPathWrongBottomProof tests that accounts in one bottom level proof don't pass
// if given another bottom level proof. Tests at least 3 accounts from each batch.
func TestVerifyProofPathWrongBottomProof(t *testing.T) {
	if len(ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")) < 2 {
		t.Skip("Need at least 2 batches for this test")
	}

	// Get batch 0 accounts
	batch0 := ReadDataFromFile[ProofElements]("out/secret/test_data_0.json")
	if len(batch0.Accounts) < 3 {
		t.Fatalf("Batch 0 needs at least 3 accounts for this test, but has %d", len(batch0.Accounts))
	}

	// Get batch 1 accounts
	batch1 := ReadDataFromFile[ProofElements]("out/secret/test_data_1.json")
	if len(batch1.Accounts) < 3 {
		t.Fatalf("Batch 1 needs at least 3 accounts for this test, but has %d", len(batch1.Accounts))
	}

	// Get the proofs
	bottomProof0 := ReadDataFromFile[CompletedProof]("out/public/test_proof_0.json")
	bottomProof1 := ReadDataFromFile[CompletedProof]("out/public/test_proof_1.json")
	midProof0 := ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_0.json")
	topProof := ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")

	// Test at least 3 accounts from batch 0 with bottomProof1
	// They should all fail verification
	for i := 0; i < 3; i++ {
		account := batch0.Accounts[i]
		t.Logf("Testing batch0 account %d with bottom proof 1", i)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected verifying batch0 account %d with bottom proof 1 to panic, but it didn't", i)
				}
			}()

			accountHash := circuit.GoComputeMiMCHashForAccount(account)
			VerifyProofPath(accountHash, bottomProof1, midProof0, topProof)
		}()
	}

	// Test at least 3 accounts from batch 1 with bottomProof0
	// They should all fail verification
	for i := 0; i < 3; i++ {
		account := batch1.Accounts[i]
		t.Logf("Testing batch1 account %d with bottom proof 0", i)

		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("Expected verifying batch1 account %d with bottom proof 0 to panic, but it didn't", i)
				}
			}()

			accountHash := circuit.GoComputeMiMCHashForAccount(account)
			VerifyProofPath(accountHash, bottomProof0, midProof0, topProof)
		}()
	}
}
