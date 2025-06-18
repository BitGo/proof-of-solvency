package core

import (
	"encoding/json"
	"os"
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
)

func ConvertProofToGoAccount(proof CompletedProof) circuit.GoAccount {
	if proof.AssetSum == nil {
		panic("AssetSum is nil, cannot convert to GoAccount")
	}
	return circuit.GoAccount{
		UserId:  proof.MerkleRoot,
		Balance: *proof.AssetSum,
	}
}

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

func writeJson(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic("Couldn't close file" + err.Error())
		}
	}(file)

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func WriteDataToFile[D ProofElements | CompletedProof | circuit.GoAccount](filePath string, data D) {
	// if writing GoAccount or ProofElements, first convert to corresponding raw data interface
	// then write to file
	switch v := any(data).(type) {
	case circuit.GoAccount:
		err := writeJson(filePath, circuit.ConvertGoAccountToRawGoAccount(v))
		if err != nil {
			panic("Error writing raw go account to file: " + err.Error())
		}
	case ProofElements:
		err := writeJson(filePath, ConvertProofElementsToRawProofElements(v))
		if err != nil {
			panic("Error writing raw proof elements to file: " + err.Error())
		}
	default:
		err := writeJson(filePath, data)
		if err != nil {
			panic("Error writing completed proof to file: " + err.Error())
		}
	}
}

func readJson(filePath string, data interface{}) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			panic("Error closing file: " + err.Error())
		}
	}(file)

	decoder := json.NewDecoder(file)
	return decoder.Decode(data)
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
			panic("Error reading raw go account from file: " + err.Error())
		}
		return any(circuit.ConvertRawGoAccountToGoAccount(rawData)).(D)
	case ProofElements:
		var rawProofElements RawProofElements
		err := readJson(filePath, &rawProofElements)
		if err != nil {
			panic("Error reading raw proof elements from file: " + err.Error())
		}
		return any(ConvertRawProofElementsToProofElements(rawProofElements)).(D)
	default:
		err := readJson(filePath, &data)
		if err != nil {
			panic("Error reading completed proof from file: " + err.Error())
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

func panicOnError(err error, messagePrefix string) {
	if err != nil {
		panic(messagePrefix + ": " + err.Error())
	}
}
