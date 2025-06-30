package core

import (
	"encoding/json"
	"math/big"
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
		panicOnError(
			writeJson(filePath, circuit.ConvertGoAccountToRawGoAccount(v)),
			"error writing raw go account to file",
		)
	case ProofElements:
		panicOnError(
			writeJson(filePath, ConvertProofElementsToRawProofElements(v)),
			"error writing raw proof elements to file",
		)
	case CompletedProof:
		// convert the asset sum to a slice of strings before writing
		var rawAssetSum *[]string
		if v.AssetSum != nil {
			convertedAssetSum := make([]string, len(*v.AssetSum))
			for i, asset := range *v.AssetSum {
				convertedAssetSum[i] = asset.String()
			}
			rawAssetSum = &convertedAssetSum
		} else {
			rawAssetSum = nil
		}

		rawCompletedProof := RawCompletedProof{
			Proof:                      v.Proof,
			VerificationKey:            v.VerificationKey,
			MerkleRoot:                 v.MerkleRoot,
			MerkleRootWithAssetSumHash: v.MerkleRootWithAssetSumHash,
			MerklePath:                 v.MerklePath,
			MerklePosition:             v.MerklePosition,
			MerkleNodes:                v.MerkleNodes,
			AssetSum:                   rawAssetSum,
		}

		panicOnError(
			writeJson(filePath, rawCompletedProof),
			"error writing raw completed proof to file",
		)
	default:
		panicOnError(writeJson(filePath, data), "error writing data to file")
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

func ReadDataFromFile[D ProofElements | CompletedProof | circuit.GoAccount | UserVerificationElements](filePath string) D {
	var data D

	// if reading GoAccount, ProofElements, or UserVerificationElements, first read as the corresponding
	// raw data interface, then convert to the actual interface
	switch any(data).(type) {
	case circuit.GoAccount:
		var rawData circuit.RawGoAccount
		panicOnError(readJson(filePath, &rawData), "error reading raw go account from file")
		return any(circuit.ConvertRawGoAccountToGoAccount(rawData)).(D)
	case ProofElements:
		var rawProofElements RawProofElements
		panicOnError(readJson(filePath, &rawProofElements), "error reading raw proof elements from file")
		return any(ConvertRawProofElementsToProofElements(rawProofElements)).(D)
	case UserVerificationElements:
		var rawUserElements struct {
			AccountData    circuit.RawGoAccount
			MerklePath     []Hash
			MerklePosition int
		}
		panicOnError(readJson(filePath, &rawUserElements), "error reading raw user verification elements from file")
		actualUserElements := UserVerificationElements{
			AccountData:    circuit.ConvertRawGoAccountToGoAccount(rawUserElements.AccountData),
			MerklePath:     rawUserElements.MerklePath,
			MerklePosition: rawUserElements.MerklePosition,
		}
		return any(actualUserElements).(D)
	case CompletedProof:
		var rawCompletedProof struct {
			Proof                      string
			VerificationKey            string
			MerkleRoot                 []byte
			MerkleRootWithAssetSumHash []byte
			MerklePath                 []Hash
			MerklePosition             int
			MerkleNodes                [][]Hash
			AssetSum                   *[]string
		}
		panicOnError(readJson(filePath, &rawCompletedProof), "error reading raw completed proof from file")

		// convert the raw asset sum to a circuit.GoBalance
		var actualAssetSum *circuit.GoBalance
		if rawCompletedProof.AssetSum == nil {
			actualAssetSum = nil
		} else {
			convertedAssetSum := make(circuit.GoBalance, len(*rawCompletedProof.AssetSum))
			for i, asset := range *rawCompletedProof.AssetSum {
				bigIntValue, ok := new(big.Int).SetString(asset, 10)
				if !ok {
					panic("Error converting asset sum string to big.Int: " + asset)
				}
				convertedAssetSum[i] = bigIntValue
			}
			actualAssetSum = &convertedAssetSum
		}

		actualCompletedProof := CompletedProof{
			Proof:                      rawCompletedProof.Proof,
			VerificationKey:            rawCompletedProof.VerificationKey,
			MerkleRoot:                 rawCompletedProof.MerkleRoot,
			MerkleRootWithAssetSumHash: rawCompletedProof.MerkleRootWithAssetSumHash,
			MerklePath:                 rawCompletedProof.MerklePath,
			MerklePosition:             rawCompletedProof.MerklePosition,
			MerkleNodes:                rawCompletedProof.MerkleNodes,
			AssetSum:                   actualAssetSum,
		}
		return any(actualCompletedProof).(D)

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
