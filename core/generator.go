package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"strconv"
)

func writeTestDataToFile(batchCount int, countPerBatch int) {
	var lastAccount *circuit.GoAccount
	for i := 0; i < batchCount; i++ {
		filePath := "out/secret/test_data_" + strconv.Itoa(i) + ".json"
		var secretData ProofElements
		var assetSum circuit.GoBalance
		secretData.Accounts, assetSum, secretData.MerkleRoot, secretData.MerkleRootWithAssetSumHash = circuit.GenerateTestData(countPerBatch, i+11)
		secretData.AssetSum = &assetSum
		err := writeJson(filePath, secretData)
		if err != nil {
			panic(err)
		}

		lastAccount = &secretData.Accounts[0]
	}

	if lastAccount == nil {
		panic("lastAccount is nil")
	}
	err := writeJson("out/user/test_account.json", lastAccount)
	if err != nil {
		panic(err)
	}
}

func GenerateData(batchCount int, countPerBatch int) {
	writeTestDataToFile(batchCount, countPerBatch)
}
