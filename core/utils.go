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

	// if data must be read in a "raw" format, handle the conversion accordingly
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
		var rawUserElements RawUserVerificationElements
		panicOnError(readJson(filePath, &rawUserElements), "error reading raw user verification elements from file")

		// convert the top proof's asset sum to a circuit.GoBalance
		var actualTopProofAssetSum *circuit.GoBalance
		if rawUserElements.ProofInfo.TopProof.AssetSum == nil {
			panic("reading user verification elements failed: TopProof.AssetSum is nil")
		} else {
			convertedAssetSum := make(circuit.GoBalance, len(*rawUserElements.ProofInfo.TopProof.AssetSum))
			for i, asset := range *rawUserElements.ProofInfo.TopProof.AssetSum {
				bigIntValue, ok := new(big.Int).SetString(asset, 10)
				if !ok {
					panic("Error converting asset sum string to big.Int: " + asset)
				}
				convertedAssetSum[i] = bigIntValue
			}
			actualTopProofAssetSum = &convertedAssetSum
		}

		// construct the UserVerificationElements from the raw data
		actualUserElements := UserVerificationElements{
			AccountInfo: circuit.ConvertRawGoAccountToGoAccount(rawUserElements.AccountInfo),
			ProofInfo: UserProofInfo{
				UserMerklePath:     rawUserElements.ProofInfo.UserMerklePath,
				UserMerklePosition: rawUserElements.ProofInfo.UserMerklePosition,
				BottomProof: CompletedProof{
					Proof:                      rawUserElements.ProofInfo.BottomProof.Proof,
					VerificationKey:            rawUserElements.ProofInfo.BottomProof.VerificationKey,
					MerkleRoot:                 rawUserElements.ProofInfo.BottomProof.MerkleRoot,
					MerkleRootWithAssetSumHash: rawUserElements.ProofInfo.BottomProof.MerkleRootWithAssetSumHash,
					MerklePath:                 rawUserElements.ProofInfo.BottomProof.MerklePath,
					MerklePosition:             rawUserElements.ProofInfo.BottomProof.MerklePosition,
				},
				MiddleProof: CompletedProof{
					Proof:                      rawUserElements.ProofInfo.MiddleProof.Proof,
					VerificationKey:            rawUserElements.ProofInfo.MiddleProof.VerificationKey,
					MerkleRoot:                 rawUserElements.ProofInfo.MiddleProof.MerkleRoot,
					MerkleRootWithAssetSumHash: rawUserElements.ProofInfo.MiddleProof.MerkleRootWithAssetSumHash,
					MerklePath:                 rawUserElements.ProofInfo.MiddleProof.MerklePath,
					MerklePosition:             rawUserElements.ProofInfo.MiddleProof.MerklePosition,
				},
				TopProof: CompletedProof{
					Proof:                      rawUserElements.ProofInfo.TopProof.Proof,
					VerificationKey:            rawUserElements.ProofInfo.TopProof.VerificationKey,
					MerkleRoot:                 rawUserElements.ProofInfo.TopProof.MerkleRoot,
					MerkleRootWithAssetSumHash: rawUserElements.ProofInfo.TopProof.MerkleRootWithAssetSumHash,
					AssetSum:                   actualTopProofAssetSum,
				},
			},
		}
		return any(actualUserElements).(D)
	case CompletedProof:
		var rawCompletedProof RawCompletedProof
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
