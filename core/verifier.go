package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

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

func Verify(batchCount int, account circuit.GoAccount) {
	bottomLevelProofs := ReadDataFromFiles[CompletedProof](batchCount, "out/public/test_proof_")
	// the number of mid level proofs is ceil(batchCount / 1024)
	midLevelProofs := ReadDataFromFiles[CompletedProof]((batchCount+1023)/1024, "out/public/test_mid_level_proof_")
	topLevelProof := ReadDataFromFiles[CompletedProof](1, "out/public/test_top_level_proof_")[0]
	verifyProofs(bottomLevelProofs, midLevelProofs, topLevelProof)

	accountHash := circuit.GoComputeMiMCHashForAccount(account)
	verifyInclusionInProof(accountHash, bottomLevelProofs)
}

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
