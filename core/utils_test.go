package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

func TestIntegrationComputeAccountLeavesFromAccounts(t *testing.T) {
	assert := test.NewAssert(t)

	accounts := []circuit.GoAccount{
		{UserId: []byte{1, 2}, Balance: circuit.GoBalance{
			Bitcoin:  *big.NewInt(1000000000),
			Ethereum: *big.NewInt(11111),
		}},
		{UserId: []byte{1, 3}, Balance: circuit.GoBalance{
			Bitcoin:  *big.NewInt(0),
			Ethereum: *big.NewInt(22222),
		}},
	}

	expectedLeaves := []AccountLeaf{
		{0x2d, 0x2e, 0xc7, 0xaf, 0xc0, 0xa3, 0x24, 0x20, 0x2, 0xcf, 0x68, 0x7f, 0x82, 0xd, 0xe2, 0x7c, 0x18, 0x75, 0x5e, 0x56, 0x8, 0xf4, 0xf1, 0xd2, 0xea, 0x93, 0x99, 0x17, 0xe2, 0x7e, 0xb5, 0xae},
		{0x21, 0xba, 0xbd, 0x7c, 0x2d, 0x66, 0xf5, 0xdb, 0xa8, 0x92, 0xb9, 0xc9, 0xb6, 0xac, 0xeb, 0x4f, 0xc2, 0xb9, 0x88, 0xa5, 0x4d, 0x85, 0xc, 0xe8, 0xe3, 0x57, 0x6a, 0x20, 0x8, 0x99, 0xbe, 0xaa},
	}

	actualLeaves := computeAccountLeavesFromAccounts(accounts)

	for i, leaf := range actualLeaves {
		assert.Equal(expectedLeaves[i], leaf, "Account leaves should match")
	}
}

func TestBatchProofs(t *testing.T) {
	assert := test.NewAssert(t)

	// we make completed proofs here
	proofs1 := make([]CompletedProof, 0)
	proofs2 := make([]CompletedProof, 16)
	proofs3 := make([]CompletedProof, 17)
	proofs4 := make([]CompletedProof, 32)
	proofs5 := make([]CompletedProof, 16000)

	assert.Equal(0, len(batchProofs(proofs1, 16)))
	assert.Equal(1, len(batchProofs(proofs2, 16)))
	assert.Equal(2, len(batchProofs(proofs3, 16)))
	assert.Equal(2, len(batchProofs(proofs4, 16)))
	assert.Equal(1000, len(batchProofs(proofs5, 16)))
	assert.Panics(func() { batchProofs(proofs3, 0) })
}
