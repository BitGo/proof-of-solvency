package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// verifyProof performs 2 actions:
// 1) It verifies that the proof is valid.
// 2) It verifies that the account leaves hash to the merkle root.
// It will only ever panic or return true. It will never return false.
func verifyProof(proof CompletedProof) bool {
	// first, verify snark
	var publicCircuit circuit.Circuit
	publicCircuit.MerkleRoot = proof.MerkleRoot
	publicCircuit.MerkleRootWithAssetSumHash = proof.MerkleRootWithAssetSumHash
	publicWitness, err := frontend.NewWitness(&publicCircuit, ecc.BN254.ScalarField(), frontend.PublicOnly())
	grothProof := groth16.NewProof(ecc.BN254)
	b1, err := base64.StdEncoding.DecodeString(proof.Proof)
	if err != nil {
		panic(err)
	}
	buf1 := bytes.NewBuffer(b1)
	_, err = grothProof.ReadFrom(buf1)
	if err != nil {
		panic(err)
	}
	grothVK := groth16.NewVerifyingKey(ecc.BN254)
	b2, err := base64.StdEncoding.DecodeString(proof.VK)
	if err != nil {
		panic(err)
	}
	buf2 := bytes.NewBuffer(b2)
	_, err = grothVK.ReadFrom(buf2)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(grothProof, grothVK, publicWitness)
	if err != nil {
		panic(err)
	}

	// next, verify the account leaves hash to the merkle root
	if !bytes.Equal(circuit.GoComputeMerkleRootFromHashes(proof.AccountLeaves), proof.MerkleRoot) {
		panic("account leaves do not hash to the merkle root")
	}
	return true
}

func verifyLowerLayerProofsLeadToUpperLayerProof(lowerLayerProofs []CompletedProof, upperLayerProof CompletedProof) {
	bottomLayerHashes := make([]circuit.Hash, len(lowerLayerProofs))
	for i, proof := range lowerLayerProofs {
		bottomLayerHashes[i] = proof.MerkleRootWithAssetSumHash
	}
	if !bytes.Equal(circuit.GoComputeMerkleRootFromHashes(bottomLayerHashes), upperLayerProof.MerkleRoot) {
		panic("upper layer proof does not match lower layer proofs")
	}
}

func verifyTopLayerProofMatchesAssetSum(topLayerProof CompletedProof) {
	if topLayerProof.AssetSum == nil {
		panic("top layer proof asset sum is nil")
	}
	if !bytes.Equal(circuit.GoComputeMiMCHashForAccount(ConvertProofToGoAccount(topLayerProof)), topLayerProof.MerkleRootWithAssetSumHash) {
		panic("top layer hash with asset sum does not match published asset sum")
	}
}

func verifyProofs(bottomLayerProofs []CompletedProof, midLayerProofs []CompletedProof, topLayerProof CompletedProof) {
	// first, verify the proofs are valid
	for _, proof := range bottomLayerProofs {
		if !verifyProof(proof) {
			panic("bottom layer proof verification failed")
		}
	}
	for _, proof := range midLayerProofs {
		if !verifyProof(proof) {
			panic("mid layer proof verification failed")
		}
	}
	if !verifyProof(topLayerProof) {
		panic("top layer proof verification failed")
	}

	// next, verify that the bottom layer proofs lead to the mid layer proofs
	bottomLevelProofsBatched := batchProofs(bottomLayerProofs, 1024)
	if len(bottomLevelProofsBatched) != len(midLayerProofs) {
		panic("bottom layer proofs and mid layer proofs do not match")
	}
	for i, batch := range bottomLevelProofsBatched {
		verifyLowerLayerProofsLeadToUpperLayerProof(batch, midLayerProofs[i])
	}

	// finally, verify that the mid layer proofs lead to the top layer proof
	verifyLowerLayerProofsLeadToUpperLayerProof(midLayerProofs, topLayerProof)
	verifyTopLayerProofMatchesAssetSum(topLayerProof)
}

// verifyInclusionInProof verifies that an account with hash accountHash is in one of the proofs provided.
func verifyInclusionInProof(accountHash circuit.Hash, bottomLayerProofs []CompletedProof) {
	for _, proof := range bottomLayerProofs {
		for _, leaf := range proof.AccountLeaves {
			if bytes.Equal(leaf, accountHash) {
				return
			}
		}
	}
	panic("account not found in any proof")
}

// VerifyProofPath is the flagship verification method.
// VerifyProofPath verifies that the account hash is included in the bottom layer proof's MerkleRoot,
// that the account balance is included in the *secret* bottomLayerProof.AssetSum,
// that the bottom layer proof MerkleTree and *secret* AssetSum hash to bottomLayerProof.MerkleRootWithAssetSumHash,
// that the bottom layer proof's MerkleRootWithAssetSumHash is included in the mid layer proof's MerkleRoot,
// and repeat the earlier steps for the mid and top layer proofs.
// It also verifies that the top layer proof's MerkleRootWithAssetSumHash matches the MerkleRoot and published AssetSum.
func VerifyProofPath(accountHash circuit.Hash, bottomLayerProof CompletedProof, midLayerProof CompletedProof, topLayerProof CompletedProof) {
	if !verifyProof(bottomLayerProof) {
		panic("bottom layer proof verification failed")
	}
	if !verifyProof(midLayerProof) {
		panic("mid layer proof verification failed")
	}
	if !verifyProof(topLayerProof) {
		panic("top layer proof verification failed")
	}
	verifyInclusionInProof(accountHash, []CompletedProof{bottomLayerProof})
	verifyInclusionInProof(bottomLayerProof.MerkleRootWithAssetSumHash, []CompletedProof{midLayerProof})
	verifyInclusionInProof(midLayerProof.MerkleRootWithAssetSumHash, []CompletedProof{topLayerProof})

	verifyTopLayerProofMatchesAssetSum(topLayerProof)
}

// Verify should primarily be used to verify the proofs after running prover..
// Verify verifies that account is included in one of the bottom level proofs, and that every proof is valid and leads
// to a higher level proof. Verify uses hardcoded file names to read the proofs from disk.
func Verify(batchCount int, account circuit.GoAccount) {
	bottomLevelProofs := ReadDataFromFiles[CompletedProof](batchCount, "out/public/test_proof_")
	// the number of mid level proofs is ceil(batchCount / 1024)
	midLevelProofs := ReadDataFromFiles[CompletedProof]((batchCount+1023)/1024, "out/public/test_mid_level_proof_")
	topLevelProof := ReadDataFromFiles[CompletedProof](1, "out/public/test_top_level_proof_")[0]
	verifyProofs(bottomLevelProofs, midLevelProofs, topLevelProof)

	accountHash := circuit.GoComputeMiMCHashForAccount(account)
	verifyInclusionInProof(accountHash, bottomLevelProofs)
}
