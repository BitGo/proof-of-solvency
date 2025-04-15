package core

import "bitgo.com/proof_of_reserves/circuit"

func main() {
	batchCount := 10
	GenerateData(batchCount, 16)
	Prove(batchCount)
	account := ReadDataFromFile[circuit.GoAccount]("out/user/test_account.json")
	Verify(batchCount, account)
	print("Proof succeeded!")
}
