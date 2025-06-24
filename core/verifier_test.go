package core

import (
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
)

var proofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_proof_0.json")
var proofLower1 = ReadDataFromFile[CompletedProof]("testdata/test_proof_1.json")
var proofMid = ReadDataFromFile[CompletedProof]("testdata/test_mid_level_proof_0.json")
var proofTop = ReadDataFromFile[CompletedProof]("testdata/test_top_level_proof_0.json")

// var altProofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_alt_proof_0.json")
// var altProofMid = ReadDataFromFile[CompletedProof]("testdata/test_alt_mid_level_proof_0.json")
var altProofTop = ReadDataFromFile[CompletedProof]("testdata/test_alt_top_level_proof_0.json")

var testData0 = ReadDataFromFile[ProofElements]("testdata/test_data_0.json")
var testData1 = ReadDataFromFile[ProofElements]("testdata/test_data_1.json")

// var testAltData0 = ReadDataFromFile[ProofElements]("testdata/test_alt_data_0.json")

func TestVerifyProofPasses(t *testing.T) {
	// should return nil for valid proofs
	if err := verifyProof(proofLower0); err != nil {
		t.Errorf("expected verifyProof to return nil for valid lower proof 0, got error: %v", err)
	}
	if err := verifyProof(proofLower1); err != nil {
		t.Errorf("expected verifyProof to return nil for valid lower proof 1, got error: %v", err)
	}
	if err := verifyProof(proofMid); err != nil {
		t.Errorf("expected verifyProof to return nil for valid mid proof, got error: %v", err)
	}
	if err := verifyProof(proofTop); err != nil {
		t.Errorf("expected verifyProof to return nil for valid top proof, got error: %v", err)
	}

	// also check with random merkle nodes (should pass)
	proofLowerModifiedMerkleNodes := proofLower0
	proofLowerModifiedMerkleNodes.MerkleNodes = [][]Hash{{{0x56, 0x78}}}
	if err := verifyProof(proofLowerModifiedMerkleNodes); err != nil {
		t.Errorf("expected verifyProof to return nil for valid lower proof 0 with random merkle nodes, got error: %v", err)
	}
}

func TestVerifyProofFails(t *testing.T) {
	// invalid proof data
	invalidProof := CompletedProof{
		Proof:                      "dummy",
		VK:                         "stuff",
		MerkleRoot:                 []byte{0x56, 0x78},
		MerkleRootWithAssetSumHash: []byte{0x9a, 0xbc},
	}

	// modified merkle root
	proofLowerModifiedMerkleRoot := proofLower0
	proofLowerModifiedMerkleRoot.MerkleRoot = proofLower1.MerkleRoot

	// modified merkle root with asset sum hash
	proofLowerModifiedMerkleRootAssetSumHash := proofLower0
	proofLowerModifiedMerkleRootAssetSumHash.MerkleRootWithAssetSumHash = proofLower1.MerkleRootWithAssetSumHash

	// modified verification key
	proofLowerModifiedVK := proofLower0
	proofLowerModifiedVK.VK = "invalidVKdataThatWillFail"

	// modifying the proof string itself
	modifiedProof := proofLower0
	modifiedProof.Proof = "AAAA" + modifiedProof.Proof[4:]

	// test cases
	tests := []struct {
		name  string
		proof CompletedProof
	}{
		{"Invalid proof data", invalidProof},
		{"Invalid merkle root", proofLowerModifiedMerkleRoot},
		{"Invalid merkle root with asset sum hash", proofLowerModifiedMerkleRootAssetSumHash},
		{"Invalid verification key", proofLowerModifiedVK},
		{"Modified proof string", modifiedProof},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyProof(tt.proof); err == nil {
				t.Errorf("expected verifyProof to return error for %s", tt.name)
			}
		})
	}
}

func TestVerifyMerklePathPasses(t *testing.T) {
	// generate valid merkle tree and valid paths for all accounts
	accounts := testData0.Accounts
	merkleNodes := circuit.GoComputeMerkleTreeNodesFromAccounts(accounts)
	merkleRoot := merkleNodes[0][0]

	// make sure passes
	for i := range testData0.Accounts {
		accountHash := circuit.GoComputeMiMCHashForAccount(accounts[i])
		accountPath := circuit.ComputeMerklePath(i, merkleNodes)
		if err := verifyMerklePath(accountHash, i, accountPath, merkleRoot); err != nil {
			t.Errorf("expected verifyMerklePath to return nil for valid path for account %d, got error: %v", i, err)
		}
	}

}

func TestVerifyMerklePathFails(t *testing.T) {
	// generate a valid merkle tree and path to start with
	accounts := testData0.Accounts
	merkleNodes := circuit.GoComputeMerkleTreeNodesFromAccounts(accounts)
	accountHash := circuit.GoComputeMiMCHashForAccount(accounts[0])
	accountPath := circuit.ComputeMerklePath(0, merkleNodes)
	merkleRoot := merkleNodes[0][0]

	// generate an invalid hash
	invalidHash := []byte{0x12, 0x34, 0x56, 0x78}

	// generate invalid paths
	invalidPathTooShort := accountPath[:len(accountPath)-1] // Missing last element
	invalidPathTooLong := append(append([]circuit.Hash{}, accountPath...), circuit.Hash{0x12, 0x34})
	invalidPathRandom := append(append([]circuit.Hash{}, accountPath[:3]...), append([]circuit.Hash{{0x21, 0x22}}, accountPath[4:]...)...)

	// Generate invalid root
	invalidRoot := []byte{0x90, 0xab, 0xcd, 0xef}

	tests := []struct {
		name     string
		hash     circuit.Hash
		position int
		path     []circuit.Hash
		root     circuit.Hash
	}{
		{"Invalid hash", invalidHash, 0, accountPath, merkleRoot},
		{"Path too short", accountHash, 0, invalidPathTooShort, merkleRoot},
		{"Path too long", accountHash, 0, invalidPathTooLong, merkleRoot},
		{"Path messed up in middle", accountHash, 0, invalidPathRandom, merkleRoot},
		{"Invalid root", accountHash, 0, accountPath, invalidRoot},
		{"Wrong position", accountHash, 1, accountPath, invalidRoot},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := verifyMerklePath(tt.hash, tt.position, tt.path, tt.root); err == nil {
				t.Errorf("expected verifyMerklePath to fail for %s", tt.name)
			}
		})
	}
}
