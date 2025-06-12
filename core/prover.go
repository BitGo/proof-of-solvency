package core

import (
	"bytes"
	"encoding/base64"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// AccountLeaf is a []byte alias for readability.
type AccountLeaf = []byte

// PartialProof contains the results of compiling and setting up a circuit.
type PartialProof struct {
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
	cs constraint.ConstraintSystem
}

// ProofElements is an input to the prover. It contains sensitive data and should not be published.
type ProofElements struct {
	Accounts []circuit.GoAccount
	// AssetSum is not optional, but marshalling fails if it is not a pointer.
	AssetSum                   *circuit.GoBalance
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
}

// RawProofElements is contains all the same items as ProofElements, except the accounts are RawGoAccounts
// should be used when writing to a json file or reading directly from a json file
type RawProofElements struct {
	Accounts                   []circuit.RawGoAccount
	AssetSum                   *circuit.GoBalance
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
}

// CompletedProof is an output of the prover. It contains the proof and public data. It can be published.
type CompletedProof struct {
	Proof                      string
	VK                         string
	AccountLeaves              []AccountLeaf
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
	// AssetSum is optional.
	AssetSum *circuit.GoBalance
}

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
		elements.MerkleRootWithAssetSumHash = circuit.GoComputeMiMCHashForAccount(circuit.GoAccount{UserId: elements.MerkleRoot, Balance: *elements.AssetSum})
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
		panic(err)
	}
	vkBytes := bytes.Buffer{}
	_, err = cachedProof.vk.WriteTo(&vkBytes)
	if err != nil {
		panic(err)
	}

	// construct and return completed proof
	return CompletedProof{
		Proof:                      base64.StdEncoding.EncodeToString(proofBytes.Bytes()),
		VK:                         base64.StdEncoding.EncodeToString(vkBytes.Bytes()),
		AccountLeaves:              circuit.GoComputeMiMCHashesForAccounts(elements.Accounts),
		MerkleRoot:                 elements.MerkleRoot,
		AssetSum:                   elements.AssetSum,
		MerkleRootWithAssetSumHash: elements.MerkleRootWithAssetSumHash,
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
// of 1024 accounts.
func writeProofsToFiles(proofs []CompletedProof, prefix string, saveAssetSum bool) {
	for i, proof := range proofs {
		if !saveAssetSum {
			proof.AssetSum = nil
		}
		filePath := prefix + strconv.Itoa(i) + ".json"
		WriteDataToFile(filePath, proof)
	}
}

// generateNextLevelProofs generates the next level proofs by calling generateProof and treating the lower level
// proofs as accounts, with MerkleRoot as UserId and AssetSum as Balance.
func generateNextLevelProofs(currentLevelProof []CompletedProof) CompletedProof {
	var nextLevelProofElements ProofElements
	nextLevelProofElements.Accounts = make([]circuit.GoAccount, len(currentLevelProof))

	for i := 0; i < len(currentLevelProof); i++ {
		if currentLevelProof[i].AssetSum == nil {
			panic("AssetSum is nil")
		}
		// convert lower level proof to GoAccount struct
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

// main proof generation function
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
