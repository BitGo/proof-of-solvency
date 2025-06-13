package core

import (
	"math/big"
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
	}

	// does not find in non-empty proofs
	proofs = make([]CompletedProof, 100)
	proofs[0] = CompletedProof{AccountLeaves: []AccountLeaf{[]byte{0x56, 0x78}}}
	if err := verifyInclusionInProof(accountHash, proofs); err == nil {
		t.Errorf("Expected error when account not found in proofs, but got nil")
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
