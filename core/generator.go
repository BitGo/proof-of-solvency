package core

import (
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
)

// GenerateData generates test data and writes it to files for development/testing purposes.
func GenerateData(batchCount int, countPerBatch int, outDir string) {
	// create base seed for generating accounts with outDir
	baseSeed := 0
	for i := range outDir {
		baseSeed ^= int(outDir[i])
	}

	// for each batch, generate a file with test data
	for i := 0; i < batchCount; i++ {
		filePath := outDir + SECRET_DATA_PREFIX + strconv.Itoa(i) + ".json"

		var secretData ProofElements
		var assetSum circuit.GoBalance
		secretData.Accounts, assetSum, secretData.MerkleRoot, secretData.MerkleRootWithAssetSumHash = circuit.GenerateTestData(countPerBatch, baseSeed+i)
		secretData.AssetSum = &assetSum

		// write to file
		WriteDataToFile(filePath, secretData)
	}
}
