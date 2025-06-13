package core

import (
	"strconv"

	"bitgo.com/proof_of_reserves/circuit"
)

// GenerateData generates test data and writes it to files for development/testing purposes.
func GenerateData(batchCount int, countPerBatch int) {
	var lastAccount *circuit.GoAccount

	for i := 0; i < batchCount; i++ {
		filePath := "out/secret/test_data_" + strconv.Itoa(i) + ".json"

		// generate data for single batch
		var secretData ProofElements
		var assetSum circuit.GoBalance
		secretData.Accounts, assetSum, secretData.MerkleRoot, secretData.MerkleRootWithAssetSumHash = circuit.GenerateTestData(countPerBatch, i+11)
		secretData.AssetSum = &assetSum

		// write to file
		WriteDataToFile(filePath, secretData)

		lastAccount = &secretData.Accounts[0]
	}

	if lastAccount == nil {
		panic("lastAccount is nil")
	}

	// write last account to separate file to test with
	WriteDataToFile("out/user/test_account.json", *lastAccount)
}
