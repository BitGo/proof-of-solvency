package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
)

const (
	// TREE_DEPTH corresponds to a maximum of 1024 leaf nodes per Merkle tree.
	// (1024 is the maximum number of accounts per batch).
	TREE_DEPTH                              = 10
	ACCOUNTS_PER_BATCH                      = 1 << TREE_DEPTH
	INVALID_BALANCE_LENGTH_MESSAGE          = "balance must have the same length as assets"
	MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE = "number of hashes exceeds the maximum number of leaves in the Merkle tree"
)

// ModBytes is needed to calculate the number of bytes needed to replicate hashing in the circuit.
var ModBytes = len(ecc.BN254.ScalarField().Bytes())

// AssetSymbols is an array storing symbols for cryptocurrencies (i.e. mapping indices to cryptocurrencies)
var AssetSymbols = []string{"ALGO", "ARBETH", "AVAXC", "AVAXP", "BTC", "BCH", "ADA", "CSPR", "TIA",
	"COREUM", "ATOM", "DASH", "DOGE", "EOS", "ETH", "ETC", "HBAR", "LTC", "NEAR",
	"OSMO", "DOT", "POLYGON", "SEI", "SOL", "STX", "XLM", "SUI", "TRX", "XRP",
	"ZEC", "ZETA", "BLD", "BSC", "TON", "COREDAO", "BERA", "TAO", "APT", "XDC", "WEMIX"}
