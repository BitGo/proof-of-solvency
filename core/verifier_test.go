package core

import (
	"fmt"
	"math/big"
	"os"
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/test"
)

// testing constants:
const batchCount = 2
const countPerBatch = 16

var proofLower0, proofLower1, proofMid, proofTop CompletedProof
var testData0, testData1 ProofElements

// TestMain sets up the test environment by generating test data and proofs once
// for all tests to use.
func TestMain(m *testing.M) {
	// clean up output directory before running tests
	os.RemoveAll("out")
	os.MkdirAll("out/secret", 0755)
	os.MkdirAll("out/public", 0755)
	os.MkdirAll("out/user", 0755)

	// create testutildata directory
	os.MkdirAll("testutildata", 0o755)

	// generate test data with batchCount batches of countPerBatch accounts each
	GenerateData(batchCount, countPerBatch)

	// generate proofs for the test data
	Prove(batchCount)

	// read generated proofs and test data files
	proofLower0 = ReadDataFromFile[CompletedProof]("out/public/test_proof_0.json")
	proofLower1 = ReadDataFromFile[CompletedProof]("out/public/test_proof_1.json")
	proofMid = ReadDataFromFile[CompletedProof]("out/public/test_mid_level_proof_0.json")
	proofTop = ReadDataFromFile[CompletedProof]("out/public/test_top_level_proof_0.json")
	testData0 = ReadDataFromFile[ProofElements]("out/secret/test_data_0.json")
	testData1 = ReadDataFromFile[ProofElements]("out/secret/test_data_1.json")

	// run tests
	exitCode := m.Run()

	// exit with test status code
	os.Exit(exitCode)
}

// var altProofLower0 = ReadDataFromFile[CompletedProof]("testdata/test_alt_proof_0.json")
// var altProofMid = ReadDataFromFile[CompletedProof]("testdata/test_alt_mid_level_proof_0.json")
var altProofTop = ReadDataFromFile[CompletedProof]("testdata/test_alt_top_level_proof_0.json")

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

func TestVerifyBuild(t *testing.T) {
	// helper
	hasher := mimc.NewMiMC()
	hashTwoNodes := func(hash1, hash2 Hash, hash1Message, hash2Message string) Hash {
		hash, err := circuit.GoComputeHashOfTwoNodes(hasher, hash1, hash2, hash1Message, hash2Message)
		if err != nil {
			panic(err)
		}
		return hash
	}

	// create merkle nodes
	leafNodes := []Hash{{0x12, 0x34}, {0x14, 0x83}, {0x93, 0x39}, {0x82, 0x98}}
	level1 := []Hash{
		hashTwoNodes(leafNodes[0], leafNodes[1], "leaf0", "leaf1"),
		hashTwoNodes(leafNodes[2], leafNodes[3], "leaf2", "leaf3"),
	}
	root := hashTwoNodes(level1[0], level1[1], "node0", "node1")
	nodes := [][]Hash{{root}, level1, leafNodes}

	// test cases
	tests := []struct {
		name        string
		nodes       [][]Hash
		root        Hash
		depth       int
		shouldError bool
	}{
		{"valid case", nodes, root, 2, false},
		{"bad root", nodes, leafNodes[0], 2, true},
		{"bad node in middle", [][]Hash{{root}, {level1[0], root}, leafNodes}, root, 2, true},
		{"invalid depth", nodes, root, 4, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := verifyBuild(tt.nodes, tt.root, tt.depth)
			if tt.shouldError && err == nil {
				t.Errorf("expected verifyBuild to error for test %s, but it didn't.", tt.name)
			}
			if !tt.shouldError && err != nil {
				t.Errorf("expected verifyBuild to pass for valid case, got error: %v", err)
			}
		})
	}
}

func TestVerifyTopLayerProofMatchesAssetSum(t *testing.T) {
	// the top layer proof should already have a valid asset sum hash and merkle root
	if err := verifyTopLayerProofMatchesAssetSum(proofTop); err != nil {
		t.Errorf("expected verifyTopLayerProofMatchesAssetSum to pass for valid proof, got error: %v", err)
	}

	// check failure case
	emptySum := circuit.ConstructGoBalance()
	if err := verifyTopLayerProofMatchesAssetSum(CompletedProof{MerkleRoot: Hash{0x23, 0x98}, MerkleRootWithAssetSumHash: Hash{0x23, 0x98}, AssetSum: &emptySum}); err == nil {
		t.Error("expected verifyTopLayerProofMatchesAssetSum to fail for bad proof")
	}
}

func TestVerifyUser(t *testing.T) {
	assert := test.NewAssert(t)

	// get account 1 from test data
	accountPosition := 1
	account := testData0.Accounts[accountPosition]
	accountMerklePath := circuit.ComputeMerklePath(accountPosition, proofLower0.MerkleNodes)

	// proof with random merkle nodes
	bottomProofWithRandomMerkleNodes := proofLower0
	bottomProofWithRandomMerkleNodes.MerkleNodes = [][]Hash{{{0x23, 0x32}}}

	// invalid proofs
	invalidBottomProof := proofLower0
	invalidBottomProof.MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	invalidMidProof := proofMid
	invalidMidProof.MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	invalidTopProof := proofTop
	invalidTopProof.MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	// invalid proof path - bottom proof not included in mid proof
	bottomMerklePath := proofLower0.MerklePath
	invalidBottomMerklePath := make([]circuit.Hash, len(bottomMerklePath))
	copy(invalidBottomMerklePath, bottomMerklePath)
	invalidBottomMerklePath[0] = []byte{0x12, 0x34, 0x56, 0x78}

	proofLower0WithBadPath := proofLower0
	proofLower0WithBadPath.MerklePath = invalidBottomMerklePath

	// Test cases
	type TestCase struct {
		name                     string
		userVerificationElements UserVerificationElements
		bottomLayerProof         CompletedProof
		midLayerProof            CompletedProof
		topLayerProof            CompletedProof
		shouldPanic              bool
	}
	tests := []TestCase{
		{
			"Valid case with random merkle nodes",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			bottomProofWithRandomMerkleNodes,
			proofMid,
			proofTop,
			false,
		},
		{
			"Invalid account data",
			UserVerificationElements{
				AccountData:    circuit.GoAccount{UserId: []byte{0x23}},
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0,
			proofMid,
			proofTop,
			true,
		},
		{
			"Invalid balance",
			UserVerificationElements{
				AccountData: circuit.GoAccount{
					UserId:  account.UserId,
					Balance: append(circuit.GoBalance{new(big.Int).Add(new(big.Int).Set(account.Balance[0]), big.NewInt(2))}, account.Balance[1:]...),
				},
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0,
			proofMid,
			proofTop,
			true,
		},
		{
			"Invalid account merkle path",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     circuit.ComputeMerklePath(0, proofLower0.MerkleNodes),
				MerklePosition: accountPosition,
			},
			proofLower0,
			proofMid,
			proofTop,
			true,
		},
		{
			"Invalid account merkle position",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition - 1,
			},
			proofLower0,
			proofMid,
			proofTop,
			true,
		},
		{
			"Invalid bottom proof",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			invalidBottomProof,
			proofMid,
			proofTop,
			true,
		},
		{
			"Invalid mid proof",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0,
			invalidMidProof,
			proofTop,
			true,
		},
		{
			"Invalid top proof",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0,
			proofMid,
			invalidTopProof,
			true,
		},
		{
			"Invalid bottom merkle path",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0WithBadPath,
			proofMid,
			proofTop,
			true,
		},
		{
			"Mismatched proofs 1",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower0,
			proofMid,
			altProofTop,
			true,
		},
		{
			"Mismatched proofs 2",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofMid,
			proofLower0,
			proofTop,
			true,
		},
		{
			"Mismatched proofs 3",
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     accountMerklePath,
				MerklePosition: accountPosition,
			},
			proofLower1,
			proofMid,
			proofTop,
			true,
		},
		{
			"Mismatched proofs 4",
			UserVerificationElements{
				AccountData:    testData1.Accounts[4],
				MerklePath:     circuit.ComputeMerklePath(4, proofLower1.MerkleNodes),
				MerklePosition: 4,
			},
			proofLower0,
			proofMid,
			proofTop,
			true,
		},
	}

	// add tests to make sure every possible account does indeed verify
	for i, account := range testData0.Accounts {
		tests = append(tests, TestCase{
			fmt.Sprintf("Valid case: batch 0, account %d", i),
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     circuit.ComputeMerklePath(i, proofLower0.MerkleNodes),
				MerklePosition: i,
			},
			proofLower0,
			proofMid,
			proofTop,
			false,
		})
	}

	for i, account := range testData1.Accounts {
		tests = append(tests, TestCase{
			fmt.Sprintf("Valid case: batch 1, account %d", i),
			UserVerificationElements{
				AccountData:    account,
				MerklePath:     circuit.ComputeMerklePath(i, proofLower1.MerkleNodes),
				MerklePosition: i,
			},
			proofLower1,
			proofMid,
			proofTop,
			false,
		})
	}

	// run test cases
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(func() {
					VerifyUser(tt.userVerificationElements, tt.bottomLayerProof, tt.midLayerProof, tt.topLayerProof)
				})
			} else {
				assert.NotPanics(func() {
					VerifyUser(tt.userVerificationElements, tt.bottomLayerProof, tt.midLayerProof, tt.topLayerProof)
				})
			}
		})
	}
}

func TestVerifyFull(t *testing.T) {
	assert := test.NewAssert(t)

	// first create all valid/invalid material to test with:
	// create a minimal set of test data
	validBottomProofs := []CompletedProof{proofLower0, proofLower1}
	validMidProofs := []CompletedProof{proofMid}
	validTopProof := proofTop
	validAccountBatches := [][]circuit.GoAccount{testData0.Accounts, testData1.Accounts}

	// invalid bottom proof
	invalidBottomProofs := make([]CompletedProof, len(validBottomProofs))
	copy(invalidBottomProofs, validBottomProofs)
	invalidBottomProofs[0].MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	// invalid mid proof
	invalidMidProofs := make([]CompletedProof, len(validMidProofs))
	copy(invalidMidProofs, validMidProofs)
	invalidMidProofs[0].MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	// invalid top proof
	invalidTopProof := validTopProof
	invalidTopProof.MerkleRoot = []byte{0x12, 0x34, 0x56, 0x78}

	// invalid account batches - wrong order
	invalidAccountBatches := make([][]circuit.GoAccount, len(validAccountBatches))
	for i := range validAccountBatches {
		invalidAccountBatches[i] = make([]circuit.GoAccount, len(validAccountBatches[i]))
		copy(invalidAccountBatches[i], validAccountBatches[i])
	}
	if len(invalidAccountBatches[0]) > 1 {
		// swap first two accounts
		invalidAccountBatches[0][0], invalidAccountBatches[0][1] = invalidAccountBatches[0][1], invalidAccountBatches[0][0]
	}

	// too few bottom proofs
	tooFewBottomProofs := []CompletedProof{proofLower0}

	// too few mid proofs
	tooFewMidProofs := []CompletedProof{}

	// merkle path of bottom proof messed up
	bottomProofsWithBadPath := make([]CompletedProof, len(validBottomProofs))
	copy(bottomProofsWithBadPath, validBottomProofs)
	badPath := make([]Hash, len(bottomProofsWithBadPath[0].MerklePath))
	copy(badPath, bottomProofsWithBadPath[0].MerklePath)
	badPath[0] = []byte{0xde, 0xad, 0xbe, 0xef} // corrupt the path
	bottomProofsWithBadPath[0].MerklePath = badPath

	// asset sum of top proof different
	topProofWithBadAssetSum := validTopProof
	badAssetSum := circuit.ConstructGoBalance()
	badAssetSum[0].Add(badAssetSum[0], big.NewInt(100)) // change the asset sum
	topProofWithBadAssetSum.AssetSum = &badAssetSum

	// merkle nodes of bottom proof messed up
	bottomProofsWithBadNodes := make([]CompletedProof, len(validBottomProofs))
	copy(bottomProofsWithBadNodes, validBottomProofs)
	badNodesBottom := make([][]Hash, len(bottomProofsWithBadNodes[0].MerkleNodes))
	for i := range badNodesBottom {
		badNodesBottom[i] = make([]Hash, len(bottomProofsWithBadNodes[0].MerkleNodes[i]))
		copy(badNodesBottom[i], bottomProofsWithBadNodes[0].MerkleNodes[i])
	}
	// corrupt a leaf node, this will fail verifyBuild
	badNodesBottom[circuit.TreeDepth][0] = []byte{0xde, 0xad, 0xbe, 0xef}
	bottomProofsWithBadNodes[0].MerkleNodes = badNodesBottom

	// merkle nodes of mid proof messed up
	midProofsWithBadNodes := make([]CompletedProof, len(validMidProofs))
	copy(midProofsWithBadNodes, validMidProofs)
	badNodesMid := make([][]Hash, len(midProofsWithBadNodes[0].MerkleNodes))
	for i := range badNodesMid {
		badNodesMid[i] = make([]Hash, len(midProofsWithBadNodes[0].MerkleNodes[i]))
		copy(badNodesMid[i], midProofsWithBadNodes[0].MerkleNodes[i])
	}
	// corrupt a leaf node, this will fail verifyBuild
	badNodesMid[circuit.TreeDepth][0] = []byte{0xde, 0xad, 0xbe, 0xef}
	midProofsWithBadNodes[0].MerkleNodes = badNodesMid

	// merkle nodes of top proof messed up
	topProofWithBadNodes := validTopProof
	badNodesTop := make([][]Hash, len(topProofWithBadNodes.MerkleNodes))
	for i := range badNodesTop {
		badNodesTop[i] = make([]Hash, len(topProofWithBadNodes.MerkleNodes[i]))
		copy(badNodesTop[i], topProofWithBadNodes.MerkleNodes[i])
	}
	// corrupt a leaf node, this will fail verifyBuild
	badNodesTop[circuit.TreeDepth][0] = []byte{0xde, 0xad, 0xbe, 0xef}
	topProofWithBadNodes.MerkleNodes = badNodesTop

	// test cases
	tests := []struct {
		name           string
		bottomProofs   []CompletedProof
		midProofs      []CompletedProof
		topProof       CompletedProof
		accountBatches [][]circuit.GoAccount
		shouldPanic    bool
	}{
		{"Valid case", validBottomProofs, validMidProofs, validTopProof, validAccountBatches, false},
		{"Invalid bottom proof", invalidBottomProofs, validMidProofs, validTopProof, validAccountBatches, true},
		{"Invalid mid proof", validBottomProofs, invalidMidProofs, validTopProof, validAccountBatches, true},
		{"Invalid top proof", validBottomProofs, validMidProofs, invalidTopProof, validAccountBatches, true},
		{"Invalid account batches", validBottomProofs, validMidProofs, validTopProof, invalidAccountBatches, true},
		{"Too few bottom proofs", tooFewBottomProofs, validMidProofs, validTopProof, validAccountBatches, true},
		{"Too few mid proofs", validBottomProofs, tooFewMidProofs, validTopProof, validAccountBatches, true},
		{"Mismatched proofs", validBottomProofs, validMidProofs, altProofTop, validAccountBatches, true},
		{"Bad bottom proof merkle path", bottomProofsWithBadPath, validMidProofs, validTopProof, validAccountBatches, true},
		{"Bad top proof asset sum", validBottomProofs, validMidProofs, topProofWithBadAssetSum, validAccountBatches, true},
		{"Bad bottom proof merkle nodes", bottomProofsWithBadNodes, validMidProofs, validTopProof, validAccountBatches, true},
		{"Bad mid proof merkle nodes", validBottomProofs, midProofsWithBadNodes, validTopProof, validAccountBatches, true},
		{"Bad top proof merkle nodes", validBottomProofs, validMidProofs, topProofWithBadNodes, validAccountBatches, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				assert.Panics(func() {
					verifyFull(tt.bottomProofs, tt.midProofs, tt.topProof, tt.accountBatches)
				})
			} else {
				assert.NotPanics(func() {
					verifyFull(tt.bottomProofs, tt.midProofs, tt.topProof, tt.accountBatches)
				})
			}
		})
	}
}
