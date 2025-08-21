package core

import (
	"bytes"
	"encoding/base64"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// cachedProofs means that we do not need to recompile the same Circuit repeatedly.
var cachedProofs = make(map[int]PartialProof)

// generateProof for single batch of accounts
func generateProof(elements ProofElements) CompletedProof {
	// preliminary checks
	if elements.AssetSum == nil {
		panic("AssetSum is nil")
	}
	actualBalances := circuit.SumGoAccountBalances(elements.Accounts)
	if !actualBalances.Equals(*elements.AssetSum) {
		panic("Asset sum does not match")
	}

	// set merkle roots if non-existent
	if elements.MerkleRoot == nil {
		elements.MerkleRoot = circuit.GoComputeMerkleRootFromAccounts(elements.Accounts)
	}
	if elements.MerkleRootWithAssetSumHash == nil {
		elements.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{WalletId: elements.MerkleRoot, Balance: *elements.AssetSum})
	}

	// check if compiled proof cached already for this length of accounts
	proofLen := len(elements.Accounts)
	if _, ok := cachedProofs[proofLen]; !ok {
		var err error

		// create a circuit with empty accounts and all-zero asset sum
		emptyAccounts := make([]circuit.Account, proofLen)
		for i := range emptyAccounts {
			emptyAccounts[i].Balance = circuit.ConstructBalance()
		}
		c := &circuit.Circuit{
			Accounts: emptyAccounts,
			AssetSum: circuit.ConstructBalance(),
		}

		// compile, set up, and cache partial proof
		cachedProof := PartialProof{}
		cachedProof.cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
		if err != nil {
			panic("Circuit failed to compile: " + err.Error())
		}
		cachedProof.pk, cachedProof.vk, err = groth16.Setup(cachedProof.cs)
		if err != nil {
			panic("Failed to setup circuit: " + err.Error())
		}
		cachedProofs[proofLen] = cachedProof
	}

	// create witness using proof elements
	witnessInput := circuit.Circuit{
		Accounts:                   circuit.ConvertGoAccountsToAccounts(elements.Accounts),
		AssetSum:                   circuit.ConvertGoBalanceToBalance(*elements.AssetSum),
		MerkleRoot:                 elements.MerkleRoot,
		MerkleRootWithAssetSumHash: elements.MerkleRootWithAssetSumHash,
	}
	witness, err := frontend.NewWitness(&witnessInput, ecc.BN254.ScalarField())
	if err != nil {
		panic("Failed to create witness: " + err.Error())
	}

	// use cached partial proof to create a proof that witness satisfies constraints
	cachedProof := cachedProofs[proofLen]
	proof, err := groth16.Prove(cachedProof.cs, cachedProof.pk, witness)
	if err != nil {
		panic("Failed to prove witness satisfies constraints: " + err.Error())
	}

	// read proof and verification key from proof
	proofBytes := bytes.Buffer{}
	_, err = proof.WriteTo(&proofBytes)
	if err != nil {
		panic("Failed to read proof bytes from proof: " + err.Error())
	}
	vkBytes := bytes.Buffer{}
	_, err = cachedProof.vk.WriteTo(&vkBytes)
	if err != nil {
		panic("Failed to read verification key bytes from proof: " + err.Error())
	}

	// construct and return completed proof (do not init MerklePath or MerklePosition as we don't know the upper level proof)
	return CompletedProof{
		Proof:                      base64.StdEncoding.EncodeToString(proofBytes.Bytes()),
		VerificationKey:            base64.StdEncoding.EncodeToString(vkBytes.Bytes()),
		MerkleRoot:                 elements.MerkleRoot,
		MerkleRootWithAssetSumHash: elements.MerkleRootWithAssetSumHash,
		MerkleNodes:                circuit.GoComputeMerkleTreeNodesFromAccounts(elements.Accounts),
		AssetSum:                   elements.AssetSum,
	}
}

// generate proofs for multiple batches
func generateProofs(proofElements []ProofElements) []CompletedProof {
	completedProofs := make([]CompletedProof, len(proofElements))
	for i := 0; i < len(proofElements); i++ {
		completedProofs[i] = generateProof(proofElements[i])
	}
	return completedProofs
}

// writeProofsToFiles writes the proofs to files with the given prefix.
// saveAssetSum should be set to true only for top level proofs, because
// otherwise the asset sum may leak information about the balance composition of each batch
// of accounts.
func writeProofsToFiles(proofs []CompletedProof, prefix string, saveAssetSum bool, saveMerkleNodes bool) {
	for i, proof := range proofs {
		if !saveAssetSum {
			proof.AssetSum = nil
		}
		if !saveMerkleNodes {
			proof.MerkleNodes = nil
		}
		filePath := prefix + strconv.Itoa(i) + ".json"
		WriteDataToFile(filePath, proof)
	}
}

// generateNextLevelProofs generates the next level proofs by calling generateProof and treating the lower level
// proofs as accounts, with MerkleRoot as WalletId and AssetSum as Balance.
func generateNextLevelProofs(currentLevelProof []CompletedProof) CompletedProof {

	// properly make accounts for next level proof using currentLevelProofs
	nextLevelProofAccounts := make([]circuit.GoAccount, len(currentLevelProof))
	for i := 0; i < len(currentLevelProof); i++ {
		if currentLevelProof[i].AssetSum == nil {
			panic("AssetSum is nil")
		}
		// convert lower level proof to GoAccount struct
		nextLevelProofAccounts[i] = circuit.GoAccount{WalletId: currentLevelProof[i].MerkleRoot, Balance: *currentLevelProof[i].AssetSum}
		if !bytes.Equal(currentLevelProof[i].MerkleRootWithAssetSumHash, circuit.GoComputeMiMCHashForAccount(nextLevelProofAccounts[i])) {
			panic("Merkle root with asset sum hash does not match")
		}
	}

	// create next level proof
	assetSum := circuit.SumGoAccountBalances(nextLevelProofAccounts)
	merkleRoot := circuit.GoComputeMerkleRootFromAccounts(nextLevelProofAccounts)
	return generateProof(ProofElements{
		Accounts:                   nextLevelProofAccounts,
		MerkleRoot:                 merkleRoot,
		AssetSum:                   &assetSum,
		MerkleRootWithAssetSumHash: circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{WalletId: merkleRoot, Balance: assetSum}),
	})
}

// setLowerLevelProofsMerklePaths sets the MerklePath and MerklePosition for each lower level proof given corresponding
// upper level proofs. Updates contents of lowerLevelProofs directly so nothing is returned.
func setLowerLevelProofsMerklePaths(lowerLevelProofs []CompletedProof, upperLevelProofs []CompletedProof) {
	for i := range lowerLevelProofs {
		upperLevelProofIndex := i / circuit.ACCOUNTS_PER_BATCH
		if upperLevelProofIndex >= len(upperLevelProofs) {
			panic("not enough upperLevelProofs given for lowerLevelProofs")
		}

		lowerLevelProofs[i].MerklePath = circuit.ComputeMerklePath(
			i%circuit.ACCOUNTS_PER_BATCH,
			upperLevelProofs[upperLevelProofIndex].MerkleNodes,
		)
		lowerLevelProofs[i].MerklePosition = i % circuit.ACCOUNTS_PER_BATCH
	}
}

// main proof generation function
func Prove(batchCount int, outDir string) {
	// bottom level proofs
	proofElements := ReadDataFromFiles[ProofElements](batchCount, outDir+SECRET_DATA_PREFIX)
	bottomLevelProofs := generateProofs(proofElements)

	// mid level proofs
	midLevelProofs := make([]CompletedProof, 0)
	for _, batch := range batchProofs(bottomLevelProofs, circuit.ACCOUNTS_PER_BATCH) {
		midLevelProofs = append(midLevelProofs, generateNextLevelProofs(batch))
	}

	// top level proof
	topLevelProof := generateNextLevelProofs(midLevelProofs)

	// set merkle paths of bottom and midlevel proofs
	setLowerLevelProofsMerklePaths(bottomLevelProofs, midLevelProofs)
	setLowerLevelProofsMerklePaths(midLevelProofs, []CompletedProof{topLevelProof})

	// write all the proofs to files
	writeProofsToFiles(bottomLevelProofs, outDir+BOTTOM_PROOF_PREFIX, false, true)
	writeProofsToFiles(midLevelProofs, outDir+MIDDLE_PROOF_PREFIX, false, false)
	writeProofsToFiles([]CompletedProof{topLevelProof}, outDir+TOP_PROOF_PREFIX, true, false)
}
