package core

import (
	"encoding/json"
	"os"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
)

func writeJson(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func readJson(filePath string, data interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic(err)
		}
	}(file)

	decoder := json.NewDecoder(file)
	return decoder.Decode(data)
}

type AccountLeaf = []byte

func ConvertProofElementsToRawProofElements(p ProofElements) RawProofElements {
	return RawProofElements{
		Accounts:                   circuit.ConvertGoAccountsToRawGoAccounts(p.Accounts),
		AssetSum:                   p.AssetSum,
		MerkleRoot:                 p.MerkleRoot,
		MerkleRootWithAssetSumHash: p.MerkleRootWithAssetSumHash,
	}
}

func ConvertRawProofElementsToProofElements(rp RawProofElements) ProofElements {
	return ProofElements{
		Accounts:                   circuit.ConvertRawGoAccountsToGoAccounts(rp.Accounts),
		AssetSum:                   rp.AssetSum,
		MerkleRoot:                 rp.MerkleRoot,
		MerkleRootWithAssetSumHash: rp.MerkleRootWithAssetSumHash,
	}
}

func ReadDataFromFile[D ProofElements | CompletedProof | circuit.GoAccount](filePath string) D {
	var data D

	// if reading GoAccount or ProofElements, first read as the corresponding raw data interface
	// then convert to the actual interface
	switch any(data).(type) {
	case circuit.GoAccount:
		var rawData circuit.RawGoAccount
		err := readJson(filePath, &rawData)
		if err != nil {
			panic(err)
		}
		return any(circuit.ConvertRawGoAccountToGoAccount(rawData)).(D)
	case ProofElements:
		var rawProofElements RawProofElements
		err := readJson(filePath, &rawProofElements)
		if err != nil {
			panic(err)
		}
		return any(ConvertRawProofElementsToProofElements(rawProofElements)).(D)
	default:
		err := readJson(filePath, &data)
		if err != nil {
			panic(err)
		}
		return data
	}

}

func ReadDataFromFiles[D ProofElements | CompletedProof](batchCount int, prefix string) []D {
	proofElements := make([]D, batchCount)
	for i := 0; i < batchCount; i++ {
		file := ReadDataFromFile[D](prefix + strconv.Itoa(i) + ".json")
		proofElements[i] = file
	}
	return proofElements
}

func computeAccountLeavesFromAccounts(accounts []circuit.GoAccount) (accountLeaves []AccountLeaf) {
	accountLeaves = make([]AccountLeaf, len(accounts))
	for i, account := range accounts {
		accountLeaves[i] = circuit.GoComputeMiMCHashForAccount(account)
	}
	return accountLeaves
}

func batchProofs(proofs []CompletedProof, batchSize int) [][]CompletedProof {
	if batchSize <= 0 {
		panic("Batch size must be greater than 0")
	}

	batches := make([][]CompletedProof, 0)
	for i := 0; i < len(proofs); i += batchSize {
		end := i + batchSize
		if end > len(proofs) {
			end = len(proofs)
		}
		batches = append(batches, proofs[i:end])
	}
	return batches
}

func ConvertProofToGoAccount(proof CompletedProof) circuit.GoAccount {
	if proof.AssetSum == nil {
		panic("AssetSum is nil, cannot convert to GoAccount")
	}
	return circuit.GoAccount{
		UserId:  proof.MerkleRoot,
		Balance: *proof.AssetSum,
	}
}
