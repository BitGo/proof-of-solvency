package core

import (
	"math/big"
	"testing"

	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark/test"
)

func TestIntegrationComputeAccountLeavesFromAccounts(t *testing.T) {
	assert := test.NewAssert(t)
	accounts := []circuit.GoAccount{
		{UserId: []byte{1, 2}, Balance: circuit.ConstructGoBalance(big.NewInt(1000000000), big.NewInt(11111))},
		{UserId: []byte{1, 3}, Balance: circuit.ConstructGoBalance(big.NewInt(0), big.NewInt(22222))},
	}

	expectedLeaves := []AccountLeaf{
		{0x1, 0x8a, 0x24, 0xf9, 0x77, 0x3a, 0xaf, 0x74, 0x41, 0x1d, 0x2d, 0x6b, 0x4f, 0xc0, 0xe8, 0xc1, 0x3, 0x7, 0xd3, 0x84, 0x34, 0xf8, 0xf, 0x77, 0xa0, 0x55, 0x7, 0xf8, 0xee, 0xc4, 0xa, 0xb1},
		{0x25, 0x4d, 0x52, 0xf9, 0x5d, 0x98, 0x4c, 0x35, 0x43, 0xd0, 0xab, 0xff, 0x7d, 0xb1, 0xf, 0x19, 0x3b, 0xa6, 0x53, 0xab, 0x22, 0xe7, 0x1, 0xe4, 0x44, 0x52, 0x11, 0x45, 0xfc, 0x53, 0xbc, 0xcd},
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
