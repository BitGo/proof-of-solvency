package core

import (
	"math/big"
	"strings"
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark/test"
)

var proofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_proof_0.json")
var proofLower1 = ReadDataFromFile[CompletedProof]("testdata/test_proof_1.json")
var proofMid = ReadDataFromFile[CompletedProof]("testdata/test_mid_level_proof_0.json")
var proofTop = ReadDataFromFile[CompletedProof]("testdata/test_top_level_proof_0.json")

var altProofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_alt_proof_0.json")
var altProofMid = ReadDataFromFile[CompletedProof]("testdata/test_alt_mid_level_proof_0.json")
var altProofTop = ReadDataFromFile[CompletedProof]("testdata/test_alt_top_level_proof_0.json")

func TestVerifyInclusionInProof(t *testing.T) {
	accountHash := []byte{0x12, 0x34}
	proof := CompletedProof{AccountLeaves: []AccountLeaf{accountHash}}

	// finds when first item
	if err := verifyInclusionInProof(accountHash, []CompletedProof{proof}); err != nil {
		t.Errorf("Expected account to be found in proof, but got error: %v", err)
	}

	// finds in not first item
	proofs := make([]CompletedProof, 100)
	proofs[99] = proof
	if err := verifyInclusionInProof(accountHash, proofs); err != nil {
		t.Errorf("Expected account to be found in proof at index 99, but got error: %v", err)
	}

	// does not find in empty proofs
	proofs = make([]CompletedProof, 0)
	if err := verifyInclusionInProof(accountHash, proofs); err == nil {
		t.Errorf("Expected error for empty proofs, but got nil")
	} else {
		expectedErrMsg := "No proofs provided to check for account inclusion"
		if err.Error() != expectedErrMsg {
			t.Errorf("Expected error message '%s', got: '%s'", expectedErrMsg, err.Error())
		}
	}

	// does not find in non-empty proofs
	proofs = make([]CompletedProof, 100)
	proofs[0] = CompletedProof{AccountLeaves: []AccountLeaf{[]byte{0x56, 0x78}}}
	if err := verifyInclusionInProof(accountHash, proofs); err == nil {
		t.Errorf("Expected error when account not found in proofs, but got nil")
	} else {
		expectedErrPrefix := "Account with hash "
		if !strings.Contains(err.Error(), expectedErrPrefix) {
			t.Errorf("Expected error to contain '%s', got: '%s'", expectedErrPrefix, err.Error())
		}
	}
}

func TestVerifyProofFails(t *testing.T) {
	proof := CompletedProof{
		Proof:                      "dummy",
		VK:                         "stuff",
		AccountLeaves:              []AccountLeaf{{0x12, 0x34}},
		MerkleRoot:                 []byte{0x56, 0x78},
		MerkleRootWithAssetSumHash: []byte{0x9a, 0xbc},
	}
	proofLowerModifiedMerkleRoot := proofLower0
	proofLowerModifiedMerkleRoot.MerkleRoot = []byte{0x56, 0x78}

	proofLowerModifiedMerkleRootAssetSumHash := proofLower0
	proofLowerModifiedMerkleRootAssetSumHash.MerkleRootWithAssetSumHash = []byte{0x56, 0x78}

	// Should return error for invalid proofs
	if err := verifyProof(proof); err == nil {
		t.Errorf("Expected verifyProof to return error for invalid proof")
	}
	if err := verifyProof(proofLowerModifiedMerkleRoot); err == nil {
		t.Errorf("Expected verifyProof to return error when merkle root is invalid")
	}
	if err := verifyProof(proofLowerModifiedMerkleRootAssetSumHash); err == nil {
		t.Errorf("Expected verifyProof to return error when merkle root with asset sum hash is invalid")
	}
}

func TestVerifyProofPasses(t *testing.T) {
	// Should return nil for valid proofs
	if err := verifyProof(proofLower0); err != nil {
		t.Errorf("Expected verifyProof to return nil for valid lower proof 0, got error: %v", err)
	}
	if err := verifyProof(proofLower1); err != nil {
		t.Errorf("Expected verifyProof to return nil for valid lower proof 1, got error: %v", err)
	}
	if err := verifyProof(proofMid); err != nil {
		t.Errorf("Expected verifyProof to return nil for valid mid proof, got error: %v", err)
	}
	if err := verifyProof(proofTop); err != nil {
		t.Errorf("Expected verifyProof to return nil for valid top proof, got error: %v", err)
	}
}

func TestVerifyProofsFailsWhenIncomplete(t *testing.T) {
	assert := test.NewAssert(t)

	assert.Panics(func() { verifyProofs([]CompletedProof{proofLower0}, []CompletedProof{proofMid}, proofTop) }, "should panic when proofs are incomplete")
	assert.Panics(func() {
		verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{proofMid}, CompletedProof{})
	}, "should panic when proofs are incomplete")
}

func TestVerifyProofsFailsWhenTopLevelAssetSumMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	incorrectProofTop := proofTop
	incorrectProofTop.AssetSum = nil

	assert.Panics(func() {
		verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{proofMid}, incorrectProofTop)
	}, "should panic when asset sum is nil")

	assetSum := make(circuit.GoBalance, circuit.GetNumberOfAssets())
	assetSum[0] = big.NewInt(1)
	assetSum[1] = big.NewInt(1)
	incorrectProofTop.AssetSum = &assetSum

	assert.Panics(func() {
		verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{proofMid}, incorrectProofTop)
	}, "should panic when asset sum is wrong")
}

func TestVerifyProofsFailsWhenBottomLayerProofsMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	incorrectProofMid := proofMid
	incorrectProofMid.MerkleRoot = []byte{0x56, 0x78}

	// we want to correct the top proof so we ensure that it's the mid proof check that fails
	correctedProofTop := proofTop
	correctedProofTop.MerkleRoot = circuit.GoComputeMerkleRootFromHashes([]circuit.Hash{proofMid.MerkleRootWithAssetSumHash})
	assert.NotPanics(func() {
		verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{proofMid}, correctedProofTop)
	})

	assert.Panics(func() {
		verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{incorrectProofMid}, correctedProofTop)
	}, "should panic when mid layer proof is incorrect")
}

func TestVerifyProofsPasses(t *testing.T) {
	verifyProofs([]CompletedProof{proofLower0, proofLower1}, []CompletedProof{proofMid}, proofTop)
}

func TestVerifyProofPath(t *testing.T) {
	assert := test.NewAssert(t)

	// Valid proofs pass
	VerifyProofPath(proofLower0.AccountLeaves[0], proofLower0, proofMid, proofTop)
	VerifyProofPath(proofLower1.AccountLeaves[len(proofLower1.AccountLeaves)-1], proofLower1, proofMid, proofTop)
	VerifyProofPath(altProofLower0.AccountLeaves[0], altProofLower0, altProofMid, altProofTop)

	// Test with invalid proofs
	assert.Panics(func() { VerifyProofPath(proofLower0.AccountLeaves[0], proofLower1, proofMid, proofTop) }, "should panic when account is not included")
	assert.Panics(func() { VerifyProofPath(proofLower0.AccountLeaves[0], proofLower0, proofMid, CompletedProof{}) }, "should panic when proofs are incomplete")

	incorrectProofTop := proofTop

	assetSum := make(circuit.GoBalance, circuit.GetNumberOfAssets())
	assetSum[0] = big.NewInt(123)
	assetSum[1] = big.NewInt(456)
	incorrectProofTop.AssetSum = &assetSum
	assert.Panics(func() { VerifyProofPath(proofLower0.AccountLeaves[0], proofLower0, proofMid, incorrectProofTop) }, "should panic when asset sum is incorrect")
	assert.Panics(func() { VerifyProofPath(proofLower0.AccountLeaves[0], proofLower0, proofMid, altProofTop) }, "should panic when mid proof does not link to top proof")
	assert.Panics(func() { VerifyProofPath(proofLower0.AccountLeaves[0], proofLower0, altProofMid, proofTop) }, "should panic when bottom proof does not link to mid proof")
}

func TestVerifyProofWithMalformedData(t *testing.T) {
	// Test with nil AccountLeaves
	proofWithNilLeaves := proofLower0
	proofWithNilLeaves.AccountLeaves = nil
	if err := verifyProof(proofWithNilLeaves); err == nil {
		t.Errorf("Expected error when AccountLeaves is nil")
	} else {
		// Verify the error message
		expectedErrMsg := "Account leaves do not hash to the merkle root"
		if err.Error() != expectedErrMsg {
			t.Errorf("Expected error message '%s', got: '%s'", expectedErrMsg, err.Error())
		}
	}

	// Test with empty AccountLeaves
	proofWithEmptyLeaves := proofLower0
	proofWithEmptyLeaves.AccountLeaves = []AccountLeaf{}
	if err := verifyProof(proofWithEmptyLeaves); err == nil {
		t.Errorf("Expected error when AccountLeaves is empty")
	}

	// Test with nil MerkleRoot
	proofWithNilMerkleRoot := proofLower0
	proofWithNilMerkleRoot.MerkleRoot = nil
	if err := verifyProof(proofWithNilMerkleRoot); err == nil {
		t.Errorf("Expected error when MerkleRoot is nil")
	}

	// Test with nil MerkleRootWithAssetSumHash
	proofWithNilMerkleRootWithAssetSumHash := proofLower0
	proofWithNilMerkleRootWithAssetSumHash.MerkleRootWithAssetSumHash = nil
	if err := verifyProof(proofWithNilMerkleRootWithAssetSumHash); err == nil {
		t.Errorf("Expected error when MerkleRootWithAssetSumHash is nil")
	}

	// Test with corrupted Proof encoding
	proofWithCorruptedProof := proofLower0
	proofWithCorruptedProof.Proof = "notvalidbase64@"
	if err := verifyProof(proofWithCorruptedProof); err == nil {
		t.Errorf("Expected error when Proof has invalid encoding")
	} else {
		if !strings.Contains(err.Error(), "Error decoding proof") {
			t.Errorf("Expected error to contain 'Error decoding proof', got: %s", err.Error())
		}
	}
}

func TestDataTamperingDetection(t *testing.T) {
	// Test bit-flip in merkle root
	tamperedProof := proofLower0
	if len(tamperedProof.MerkleRoot) > 0 {
		// Flip a single bit in the merkle root
		tamperedProof.MerkleRoot[0] ^= 0x01
	}

	if err := verifyProof(tamperedProof); err == nil {
		t.Errorf("Expected error for tampered merkle root")
	}

	// Test swapping AccountLeaves between proofs
	if len(proofLower0.AccountLeaves) > 0 && len(proofLower1.AccountLeaves) > 0 {
		tamperedProof0 := proofLower0
		tamperedProof1 := proofLower1

		// Swap first account leaves
		tmp := tamperedProof0.AccountLeaves[0]
		tamperedProof0.AccountLeaves[0] = tamperedProof1.AccountLeaves[0]
		tamperedProof1.AccountLeaves[0] = tmp

		if err := verifyProof(tamperedProof0); err == nil {
			t.Errorf("Expected error for tampered account leaves")
		}

		if err := verifyProof(tamperedProof1); err == nil {
			t.Errorf("Expected error for tampered account leaves")
		}
	}

	// Test with modified Proof string but same structure
	tamperedProofData := proofLower0
	originalProof := tamperedProofData.Proof
	tamperedProofData.Proof = proofLower1.Proof // Use a different valid proof that doesn't match this proof's data

	if err := verifyProof(tamperedProofData); err == nil {
		t.Errorf("Expected error for mismatched proof data")
	}

	// Restore original proof for cleanup
	tamperedProofData.Proof = originalProof
}

func TestStructuralEdgeCases(t *testing.T) {
	// Test verifyProofs with empty bottom layer proofs
	assert := test.NewAssert(t)
	assert.Panics(func() {
		verifyProofs([]CompletedProof{}, []CompletedProof{proofMid}, proofTop)
	}, "Should panic when bottom layer proofs are empty")

	// Test verifyProofs with empty mid layer proofs
	assert.Panics(func() {
		verifyProofs([]CompletedProof{proofLower0}, []CompletedProof{}, proofTop)
	}, "Should panic when mid layer proofs are empty")

	// Test cross-layer verification attacks - using a bottom proof as a mid proof
	assert.Panics(func() {
		// Try to use a bottom layer proof as a mid layer proof
		tamperedMidProof := proofLower0 // Use a bottom layer proof as a mid layer proof
		verifyProofs([]CompletedProof{proofLower1}, []CompletedProof{tamperedMidProof}, proofTop)
	}, "Should panic when using bottom layer proof as mid layer proof")

	// Test proof with all fields set to valid values but structurally invalid
	// Create a structurally valid but cryptographically invalid proof
	invalidProof := CompletedProof{
		Proof:                      proofLower0.Proof,
		VK:                         proofLower0.VK,
		AccountLeaves:              proofLower0.AccountLeaves,
		MerkleRoot:                 proofMid.MerkleRoot,                 // Mismatched root
		MerkleRootWithAssetSumHash: proofTop.MerkleRootWithAssetSumHash, // Mismatched hash
		AssetSum:                   proofTop.AssetSum,                   // Mismatched sum
	}

	if err := verifyProof(invalidProof); err == nil {
		t.Errorf("Expected error for structurally valid but cryptographically invalid proof")
	}
}
