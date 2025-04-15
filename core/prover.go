package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"bytes"
	"encoding/base64"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"strconv"
)

type PartialProof struct {
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
	cs constraint.ConstraintSystem
}

var cachedProofs = make(map[int]PartialProof)

func generateProof(elements ProofElements) CompletedProof {
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	if elements.MerkleRoot == nil {
		elements.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(elements.Accounts)
	}
	if elements.MerkleRootWithAssetSumHash == nil {
		elements.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: elements.MerkleRoot, Balance: *elements.AssetSum})
	}
	actualBalances := circuit.SumGoAccountBalances(elements.Accounts)
	if !actualBalances.Equals(*elements.AssetSum) {
		panic("Asset sum does not match")
	}

	proofLen := len(elements.Accounts)
	if _, ok := cachedProofs[proofLen]; !ok {
		var err error
		c := &circuit.Circuit{
			Accounts: make([]circuit.Account, len(elements.Accounts)),
		}
		cachedProof := PartialProof{}
		cachedProof.cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic(err)
		}
		cachedProof.pk, cachedProof.vk, err = groth16.Setup(cachedProof.cs)
		if err != nil {
			panic(err)
		}
		cachedProofs[proofLen] = cachedProof
	}
	cachedProof := cachedProofs[proofLen]
	var witnessInput circuit.Circuit
	witnessInput.Accounts = circuit.ConvertGoAccountsToAccounts(elements.Accounts)
	witnessInput.MerkleRoot = elements.MerkleRoot
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	witnessInput.AssetSum = circuit.ConvertGoBalanceToBalance(*elements.AssetSum)
	witnessInput.MerkleRootWithAssetSumHash = elements.MerkleRootWithAssetSumHash
	witness, err := frontend.NewWitness(&witnessInput, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(cachedProof.cs, cachedProof.pk, witness, backend.WithIcicleAcceleration())
	if err != nil {
		panic(err)
	}

	var completedProof CompletedProof
	b1 := bytes.Buffer{}
	_, err = proof.WriteTo(&b1)
	if err != nil {
		panic(err)
	}
	completedProof.Proof = base64.StdEncoding.EncodeToString(b1.Bytes())
	b2 := bytes.Buffer{}
	_, err = cachedProof.vk.WriteTo(&b2)
	if err != nil {
		panic(err)
	}
	completedProof.VK = base64.StdEncoding.EncodeToString(b2.Bytes())
	completedProof.AccountLeaves = computeAccountLeavesFromAccounts(elements.Accounts)
	completedProof.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(elements.Accounts)
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	completedProof.AssetSum = elements.AssetSum
	completedProof.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: completedProof.MerkleRoot, Balance: *elements.AssetSum})
	return completedProof
}

func generateProofs(proofElements []ProofElements) []CompletedProof {
	completedProofs := make([]CompletedProof, len(proofElements))
	for i := 0; i < len(proofElements); i++ {
		completedProofs[i] = generateProof(proofElements[i])
	}
	return completedProofs
}

func writeProofsToFiles(proofs []CompletedProof, prefix string, saveAssetSum bool) {
	for i, proof := range proofs {
		if !saveAssetSum {
			proof.AssetSum = nil
		}
		filePath := prefix + strconv.Itoa(i) + ".json"
		err := writeJson(filePath, proof)
		if err != nil {
			panic(err)
		}
	}
}

func generateNextLevelProofs(currentLevelProof []CompletedProof) CompletedProof {
	var nextLevelProofElements ProofElements
	nextLevelProofElements.Accounts = make([]circuit.GoAccount, len(currentLevelProof))

	for i := 0; i < len(currentLevelProof); i++ {
		if currentLevelProof[i].AssetSum == nil {
			panic("AssetSum is nil")
		}
		nextLevelProofElements.Accounts[i] = circuit.GoAccount{UserId: currentLevelProof[i].MerkleRoot, Balance: *currentLevelProof[i].AssetSum}
		if !bytes.Equal(currentLevelProof[i].MerkleRootWithAssetSumHash, circuit.GoComputeMiMCHashForAccount(nextLevelProofElements.Accounts[i])) {
			panic("Merkle root with asset sum hash does not match")
		}
	}
	nextLevelProofElements.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(nextLevelProofElements.Accounts)
	assetSum := circuit.SumGoAccountBalances(nextLevelProofElements.Accounts)
	nextLevelProofElements.AssetSum = &assetSum
	nextLevelProofElements.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: nextLevelProofElements.MerkleRoot, Balance: *nextLevelProofElements.AssetSum})
	return generateProof(nextLevelProofElements)
}

func Prove(batchCount int) (bottomLevelProofs []CompletedProof, topLevelProof CompletedProof) {
	// bottom level proofs
	proofElements := ReadDataFromFiles[ProofElements](batchCount, "out/secret/test_data_")
	bottomLevelProofs = generateProofs(proofElements)
	writeProofsToFiles(bottomLevelProofs, "out/public/test_proof_", false)

	// mid level proofs
	midLevelProofs := make([]CompletedProof, 0)
	for _, batch := range batchProofs(bottomLevelProofs, 1024) {
		midLevelProofs = append(midLevelProofs, generateNextLevelProofs(batch))
	}
	writeProofsToFiles(midLevelProofs, "out/public/test_mid_level_proof_", false)

	// top level proof
	topLevelProof = generateNextLevelProofs(midLevelProofs)
	writeProofsToFiles([]CompletedProof{topLevelProof}, "out/public/test_top_level_proof_", true)
	return bottomLevelProofs, topLevelProof
}
