package core

import (
	"testing"
)

var proofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_proof_0.json")
var proofLower1 = ReadDataFromFile[CompletedProof]("testdata/test_proof_1.json")
var proofMid = ReadDataFromFile[CompletedProof]("testdata/test_mid_level_proof_0.json")
var proofTop = ReadDataFromFile[CompletedProof]("testdata/test_top_level_proof_0.json")

var altProofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_alt_proof_0.json")
var altProofMid = ReadDataFromFile[CompletedProof]("testdata/test_alt_mid_level_proof_0.json")
var altProofTop = ReadDataFromFile[CompletedProof]("testdata/test_alt_top_level_proof_0.json")

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
