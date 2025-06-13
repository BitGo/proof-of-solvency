package core

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// verifyProof performs 2 actions:
// 1) It verifies that the proof is valid.
// 2) It verifies that the account leaves hash to the merkle root.
// Returns nil if verification passes, error if it fails
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

	// next, verify the account leaves hash to the merkle root
	if !bytes.Equal(circuit.GoComputeMerkleRootFromHashes(proof.AccountLeaves), proof.MerkleRoot) {
		return fmt.Errorf("Account leaves do not hash to the merkle root")
	}
	return nil
}

// verifyLowerLayerProofsLeadToUpperLayerProof verifies the merkle root of the upperLayerProof was computed
// from the merkleRootAssetSumHashes of the lowerLayerProofs
// Returns nil if verification passes, error if it fails
func verifyLowerLayerProofsLeadToUpperLayerProof(lowerLayerProofs []CompletedProof, upperLayerProof CompletedProof) error {
	bottomLayerHashes := make([]circuit.Hash, len(lowerLayerProofs))
	for i, proof := range lowerLayerProofs {
		bottomLayerHashes[i] = proof.MerkleRootWithAssetSumHash
	}

	computedRoot := circuit.GoComputeMerkleRootFromHashes(bottomLayerHashes)
	if !bytes.Equal(computedRoot, upperLayerProof.MerkleRoot) {
		return fmt.Errorf("Upper layer proof's Merkle root does not match what was computed from lower layer proofs")
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

func verifyProofs(bottomLayerProofs []CompletedProof, midLayerProofs []CompletedProof, topLayerProof CompletedProof) {
	// first, verify the proofs are valid
	for i, proof := range bottomLayerProofs {
		if err := verifyProof(proof); err != nil {
			panic("Bottom layer proof verification failed for proof index " + strconv.Itoa(i) + ": " + err.Error())
		}
	}
	for i, proof := range midLayerProofs {
		if err := verifyProof(proof); err != nil {
			panic("Mid layer proof verification failed for proof index " + strconv.Itoa(i) + ": " + err.Error())
		}
	}
	if err := verifyProof(topLayerProof); err != nil {
		panic("Top layer proof verification failed: " + err.Error())
	}

	// next, verify that the bottom layer proofs lead to the mid layer proofs
	bottomLevelProofsBatched := batchProofs(bottomLayerProofs, 1024)
	if len(bottomLevelProofsBatched) != len(midLayerProofs) {
		panic("Bottom layer proofs and mid layer proofs count mismatch: " +
			strconv.Itoa(len(bottomLevelProofsBatched)) + " batches of bottom proofs vs " +
			strconv.Itoa(len(midLayerProofs)) + " mid-level proofs")
	}
	for i, batch := range bottomLevelProofsBatched {
		if err := verifyLowerLayerProofsLeadToUpperLayerProof(batch, midLayerProofs[i]); err != nil {
			panic("Bottom layer proof batch " + strconv.Itoa(i) + " does not lead to mid layer proof " + strconv.Itoa(i) + ": " + err.Error())
		}
	}

	// finally, verify that the mid layer proofs lead to the top layer proof
	if err := verifyLowerLayerProofsLeadToUpperLayerProof(midLayerProofs, topLayerProof); err != nil {
		panic("Mid layer proofs do not lead to top layer proof: " + err.Error())
	}

	if err := verifyTopLayerProofMatchesAssetSum(topLayerProof); err != nil {
		panic("Top layer proof hash with asset sum does not match published asset sum: " + err.Error())
	}
}

// verifyInclusionInProof verifies that an account with hash accountHash is in one of the proofs provided.
// Returns nil if the account is found, error if it is not found
func verifyInclusionInProof(accountHash circuit.Hash, bottomLayerProofs []CompletedProof) error {
	if len(bottomLayerProofs) == 0 {
		return fmt.Errorf("No proofs provided to check for account inclusion")
	}

	for _, proof := range bottomLayerProofs {
		for _, leaf := range proof.AccountLeaves {
			if bytes.Equal(leaf, accountHash) {
				return nil
			}
		}
	}

	// If we get here, the account wasn't found
	return fmt.Errorf("Account with hash %x not found in any of the %d provided proofs",
		accountHash, len(bottomLayerProofs))
}

// VerifyProofPath is the flagship verification method.
// VerifyProofPath verifies that the account hash is included in the bottom layer proof's MerkleRoot,
// that the account balance is included in the *secret* bottomLayerProof.AssetSum,
// that the bottom layer proof MerkleTree and *secret* AssetSum hash to bottomLayerProof.MerkleRootWithAssetSumHash,
// that the bottom layer proof's MerkleRootWithAssetSumHash is included in the mid layer proof's MerkleRoot,
// and repeat the earlier steps for the mid and top layer proofs.
// It also verifies that the top layer proof's MerkleRootWithAssetSumHash matches the MerkleRoot and published AssetSum.
func VerifyProofPath(accountHash circuit.Hash, bottomLayerProof CompletedProof, midLayerProof CompletedProof, topLayerProof CompletedProof) {
	if err := verifyProof(bottomLayerProof); err != nil {
		panic("Bottom layer proof verification failed: " + err.Error())
	}
	if err := verifyProof(midLayerProof); err != nil {
		panic("Mid layer proof verification failed: " + err.Error())
	}
	if err := verifyProof(topLayerProof); err != nil {
		panic("Top layer proof verification failed: " + err.Error())
	}

	if err := verifyInclusionInProof(accountHash, []CompletedProof{bottomLayerProof}); err != nil {
		panic("Account not found in bottom layer proof: " + err.Error())
	}

	if err := verifyInclusionInProof(bottomLayerProof.MerkleRootWithAssetSumHash, []CompletedProof{midLayerProof}); err != nil {
		panic("Bottom layer proof not found in mid layer proof: " + err.Error())
	}

	if err := verifyInclusionInProof(midLayerProof.MerkleRootWithAssetSumHash, []CompletedProof{topLayerProof}); err != nil {
		panic("Mid layer proof not found in top layer proof: " + err.Error())
	}

	if err := verifyTopLayerProofMatchesAssetSum(topLayerProof); err != nil {
		panic("Top layer proof hash with asset sum does not match published asset sum: " + err.Error())
	}
}

// Verify should primarily be used to verify the proofs after running prover.
// Verify verifies that account is included in one of the bottom level proofs, and that every proof is valid and leads
// to a higher level proof. Verify uses hardcoded file names to read the proofs from disk.
func Verify(batchCount int, account circuit.GoAccount) {
	bottomLevelProofs := ReadDataFromFiles[CompletedProof](batchCount, "out/public/test_proof_")
	// the number of mid level proofs is ceil(batchCount / 1024)
	midLevelProofs := ReadDataFromFiles[CompletedProof]((batchCount+1023)/1024, "out/public/test_mid_level_proof_")
	topLevelProof := ReadDataFromFiles[CompletedProof](1, "out/public/test_top_level_proof_")[0]

	// Verify the proofs
	verifyProofs(bottomLevelProofs, midLevelProofs, topLevelProof)

	// Verify account inclusion
	accountHash := circuit.GoComputeMiMCHashForAccount(account)
	if err := verifyInclusionInProof(accountHash, bottomLevelProofs); err != nil {
		panic("Account not found in any bottom layer proof: " + err.Error())
	}
}
