package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// verifyProof verifies that the proof is valid - returns nil if verification passes, error if it fails
func verifyProof(proof CompletedProof) error {
	// first, verify snark
	// create the public witness
	publicWitness, err := frontend.NewWitness(&circuit.Circuit{
		MerkleRoot:                 proof.MerkleRoot,
		MerkleRootWithAssetSumHash: proof.MerkleRootWithAssetSumHash,
	}, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("Error creating public witness: %v", err)
	}

	// read proof bytes into groth16 proof instance
	grothProof := groth16.NewProof(ecc.BN254)
	proofBytes, err := base64.StdEncoding.DecodeString(proof.Proof)
	if err != nil {
		return fmt.Errorf("Error decoding proof: %v", err)
	}
	_, err = grothProof.ReadFrom(bytes.NewBuffer(proofBytes))
	if err != nil {
		return fmt.Errorf("Error reading proof: %v", err)
	}

	// read verification key bytes into groth16 vk instance
	grothVK := groth16.NewVerifyingKey(ecc.BN254)
	vkBytes, err := base64.StdEncoding.DecodeString(proof.VK)
	if err != nil {
		return fmt.Errorf("Error decoding verification key: %v", err)
	}
	_, err = grothVK.ReadFrom(bytes.NewBuffer(vkBytes))
	if err != nil {
		return fmt.Errorf("Error reading verification key: %v", err)
	}

	// verify public witness with proof and VK
	err = groth16.Verify(grothProof, grothVK, publicWitness)
	if err != nil {
		return fmt.Errorf("Proof verification failed: %v", err)
	}

	return nil
}

// verifyMerklePath verifies that a particular hash and merkle path lead to the given merkle root
func verifyMerklePath(hash Hash, path []Hash, root Hash) error {
	if len(path) != circuit.TreeDepth {
		return fmt.Errorf("merkle path is not of depth of tree: expected length %d, found %d", circuit.TreeDepth, len(path))
	}
	hasher := mimc.NewMiMC()
	curr := hash
	var err error
	for i, sibling := range path {
		depth := strconv.Itoa(len(path) - i)
		curr, err = circuit.GoComputeHashOfTwoNodes(hasher, curr, sibling, "current node at depth "+depth, "sibling node at depth "+depth)
		if err != nil {
			return err
		}
	}
	if !bytes.Equal(curr, root) {
		return fmt.Errorf("merkle proof path verification failed")
	}
	return nil
}

// verifyBuild verifies that the given merkle nodes are indeed part of the merkle tree with the given root.
func verifyBuild(nodes [][]Hash, root Hash, treeDepth int) error {
	if len(nodes)-1 != treeDepth {
		return fmt.Errorf("expected %d layers of nodes, found %d", treeDepth+1, len(nodes))
	}

	hasher := mimc.NewMiMC()

	// verify correct number of hashes/nodes in bottom layer
	if len(nodes[treeDepth]) != circuit.PowOfTwo(treeDepth) {
		return fmt.Errorf("invalid number of nodes for depth %d in the tree: expected %d, found %d", treeDepth, circuit.PowOfTwo(treeDepth), len(nodes[treeDepth]))
	}

	for i := treeDepth; i >= 1; i-- {
		// verify enough nodes in parent layer
		if len(nodes[i-1]) != circuit.PowOfTwo(i-1) {
			return fmt.Errorf("invalid number of nodes for depth %d in the tree: expected %d, found %d", i-1, circuit.PowOfTwo(i-1), len(nodes[i-1]))
		}

		// iteratively compute hash with children and compare with parent
		for j := 0; j < circuit.PowOfTwo(i-1); j++ {
			curr, err := circuit.GoComputeHashOfTwoNodes(hasher, nodes[i][2*j], nodes[i][2*j+1], fmt.Sprintf("node[%d][%d]", i, 2*j), fmt.Sprintf("node[%d][%d]", i, 2*j+1))
			if err != nil {
				return err
			}
			if !bytes.Equal(curr, nodes[i-1][j]) {
				return fmt.Errorf("incorrect hash found at depth %d, position %d", i-1, j)
			}
		}
	}

	// verify roots equal
	if !bytes.Equal(nodes[0][0], root) {
		return fmt.Errorf("given root doesn't match root of given merkle nodes")
	}

	return nil
}

// verifies the MerkleRootAssetSumHash of the top layer proof is indeed the hash of its merkleRoot and assetSum
// Returns nil if verification passes, error if it fails
func verifyTopLayerProofMatchesAssetSum(topLayerProof CompletedProof) error {
	if topLayerProof.AssetSum == nil {
		return fmt.Errorf("Top layer proof's AssetSum is nil")
	}

	computedHash := circuit.GoComputeMiMCHashForAccount(ConvertProofToGoAccount(topLayerProof))
	if !bytes.Equal(computedHash, topLayerProof.MerkleRootWithAssetSumHash) {
		return fmt.Errorf("Top layer proof's MerkleRootWithAssetSumHash does not match the hash computed from MerkleRoot and AssetSum")
	}
	return nil
}

// VerifyProofPath is the flagship verification method.
// VerifyProofPath verifies that the account hash is included in the bottom layer proof's MerkleRoot,
// that the account balance is included in the *secret* bottomLayerProof.AssetSum,
// that the bottom layer proof MerkleTree and *secret* AssetSum hash to bottomLayerProof.MerkleRootWithAssetSumHash,
// that the bottom layer proof's MerkleRootWithAssetSumHash is included in the mid layer proof's MerkleRoot,
// and repeat the earlier steps for the mid and top layer proofs.
// It also verifies that the top layer proof's MerkleRootWithAssetSumHash matches the MerkleRoot and published AssetSum.
func VerifyUser(accountHash Hash, accountMerklePath []Hash, bottomLayerProof CompletedProof, midLayerProof CompletedProof, topLayerProof CompletedProof) {
	// verify proofs
	panicOnError(verifyProof(bottomLayerProof), "bottom layer proof verification failed")
	panicOnError(verifyProof(midLayerProof), "mid layer proof verification failed")
	panicOnError(verifyProof(topLayerProof), "top layer proof verification failed")

	// verify inclusion of account -> bottom proof -> middle proof -> top
	panicOnError(
		verifyMerklePath(accountHash, accountMerklePath, bottomLayerProof.MerkleRoot),
		"failed to verify if account included in bottom proof",
	)
	panicOnError(
		verifyMerklePath(bottomLayerProof.MerkleRootWithAssetSumHash, bottomLayerProof.MerklePath, midLayerProof.MerkleRoot),
		"failed to verify if account included in bottom proof",
	)
	panicOnError(
		verifyMerklePath(midLayerProof.MerkleRootWithAssetSumHash, midLayerProof.MerklePath, topLayerProof.MerkleRoot),
		"failed to verify if account included in bottom proof",
	)

	// verify top layer asset sum (encoded in MerkleRootWithAssetSumHash) matches the published asset sum
	panicOnError(verifyTopLayerProofMatchesAssetSum(topLayerProof), "top layer hashed asset sum does not match published asset sum")
}

// verifyFull is used to perform full verification of generated proofs.
// It verifies that every account is included in one of the bottom level proofs, and that every proof is valid,
// has a valid Merkle path leading to the upper level proof, and has the correct merkle nodes for its merkle root.
// It also verifies the published asset sum in the top level proof matches the sum hashed with the merkle root.
// Expects that all the CompletedProofs read will contain MerkleNodes to be verified, and expects accounts to be in batches
// and in the same order they were fed into the proof generator, both at batch level and individual level.
func verifyFull(bottomLevelProofs, midLevelProofs []CompletedProof, topLevelProof CompletedProof, accountBatches [][]circuit.GoAccount) {

	// bottom level proofs (verify merkle nodes, proof, merkle path)
	for i, bottomProof := range bottomLevelProofs {
		panicOnError(
			verifyBuild(bottomProof.MerkleNodes, bottomProof.MerkleRoot, circuit.TreeDepth),
			fmt.Sprintf("merkle nodes for bottom level proof %d inconsistent with its merkle root", i),
		)
		panicOnError(verifyProof(bottomProof), fmt.Sprintf("circuit verification failed for bottom level proof %d", i))
		panicOnError(
			verifyMerklePath(bottomProof.MerkleRootWithAssetSumHash, bottomProof.MerklePath, midLevelProofs[i/1024].MerkleRoot),
			fmt.Sprintf("merkle path verification failed for bottom level proof %d", i),
		)
	}

	// mid level proofs (verify merkle nodes, proof, merkle path)
	for i, middleProof := range midLevelProofs {
		panicOnError(
			verifyBuild(middleProof.MerkleNodes, middleProof.MerkleRoot, circuit.TreeDepth),
			fmt.Sprintf("merkle nodes for mid level proof %d inconsistent with its merkle root", i),
		)
		panicOnError(verifyProof(middleProof), fmt.Sprintf("circuit verification failed for mid level proof %d", i))
		panicOnError(
			verifyMerklePath(middleProof.MerkleRootWithAssetSumHash, middleProof.MerklePath, topLevelProof.MerkleRoot),
			fmt.Sprintf("merkle path verification failed for mid level proof %d", i),
		)
	}

	// top level proof (verify merkle nodes and proof)
	panicOnError(verifyBuild(topLevelProof.MerkleNodes, topLevelProof.MerkleRoot, circuit.TreeDepth), "merkle nodes for top level proof inconsistent with merkle root")
	panicOnError(verifyProof(topLevelProof), "top level proof circuit verification failed")

	// verify account inclusion
	for i, batch := range accountBatches {
		for j, account := range batch {
			accountHash := circuit.GoComputeMiMCHashForAccount(account)
			if !bytes.Equal(accountHash, bottomLevelProofs[i].MerkleNodes[circuit.TreeDepth][j]) {
				panic(fmt.Sprintf("account %d of batch %d not found in bottom level proofs (or accounts not given in the order given to prover)", j, i))
			}
		}
	}

	// verify top layer asset sum (encoded in MerkleRootWithAssetSumHash) matches the published asset sum
	panicOnError(verifyTopLayerProofMatchesAssetSum(topLevelProof), "top layer hashed asset sum does not match published asset sum")
}

// VerifyFull should primarily be used to perform a full verification of the proofs after running prover.
// Is a wrapper around the private verifyFull and uses hardcoded file names to read the proofs and accounts from disk.
func VerifyFull(batchCount int) {

	// read accounts
	proofElements := ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")
	accounts := make([][]circuit.GoAccount, batchCount)
	for i, proofElement := range proofElements {
		accounts[i] = proofElement.Accounts
	}

	// read proofs from files
	bottomLevelProofs := ReadDataFromFiles[CompletedProof](batchCount, "out/public/test_proof_")
	// the number of mid level proofs is ceil(batchCount / 1024)
	midLevelProofs := ReadDataFromFiles[CompletedProof]((batchCount+1023)/1024, "out/public/test_mid_level_proof_")
	topLevelProof := ReadDataFromFiles[CompletedProof](1, "out/public/test_top_level_proof_")[0]

	// verify
	verifyFull(bottomLevelProofs, midLevelProofs, topLevelProof, accounts)
}
