package circuit

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Balance is an input to the circuit and is only used in this package. GoBalance is preferred elsewhere.
type Balance []frontend.Variable

// Account is an input to the circuit and is only used in this package. GoAccount is preferred elsewhere.
type Account struct {
	WalletId  frontend.Variable
	Balance Balance
}

// Circuit is the input to the proof. A complete Circuit generates a proof, and the public elements of
// the Circuit can be used to verify the proof.
type Circuit struct {
	Accounts                   []Account         `gnark:""`
	AssetSum                   Balance           `gnark:""`
	MerkleRoot                 frontend.Variable `gnark:",public"`
	MerkleRootWithAssetSumHash frontend.Variable `gnark:",public"`
}

type Hash = []byte

// GoBalance represents the balance of an account. It can be converted to Balance for use in the circuit
// through ConvertGoBalanceToBalance.
type GoBalance []*big.Int

// GoAccount represents an account. It can be converted to Account for use in the circuit
// through ConvertGoAccountToAccount.
type GoAccount struct {
	WalletId  []byte
	Balance GoBalance
}

// RawGoAccount represents an account read from file (with a string WalletId). It can be converted to
// GoAccount (to manipulate here) through ConvertRawGoAccountToAccount.
type RawGoAccount struct {
	WalletId  string
	Balance GoBalance
}
