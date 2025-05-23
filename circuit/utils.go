package circuit

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// ModBytes is needed to calculate the number of bytes needed to replicate hashing in the circuit.
var ModBytes = len(ecc.BN254.ScalarField().Bytes())

// GoBalance represents the balance of an account. It can be converted to Balance for use in the circuit
// through ConvertGoBalanceToBalance.
type GoBalance struct {
	Bitcoin  big.Int
	Ethereum big.Int
}

// GoAccount represents an account. It can be converted to Account for use in the circuit
// through ConvertGoAccountToAccount.
type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

// TODO: this function is completely unncecessary, even for testing since it only breaks the overflow constraint
// negative numbers are straight up impossible in the circuit
// padToModBytes pads the input value to ModBytes length. If the value is negative, it sign-extends the value.
func padToModBytes(value []byte, isNegative bool) (paddedValue []byte) {
	paddedValue = make([]byte, ModBytes-len(value))
	// This will never be used in the circuit because it will be greater than 64 bytes and
	// will thus fail rangechecking constraints.
	// It is implemented for convenience in testing. We should consider removing this entirely.
	if isNegative {
		for i := range paddedValue {
			paddedValue[i] = 0xFF
		}
		paddedValue[0] = 0x0F // this is 252 bits, an imperfect sign extension
	}
	paddedValue = append(paddedValue, value...)
	return paddedValue
}

// goConvertBalanceToBytes converts a GoBalance to bytes in the same way as the circuit does.
func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	value = make([]byte, 0)
	value = append(value, padToModBytes(balance.Bitcoin.Bytes(), balance.Bitcoin.Sign() == -1)...)
	value = append(value, padToModBytes(balance.Ethereum.Bytes(), balance.Ethereum.Sign() == -1)...)

	return value
}

// GoComputeMiMCHashForAccount computes the MiMC hash of the account's balance and user ID
// and returns a consistent result with hashAccount in the circuit.
func GoComputeMiMCHashForAccount(account GoAccount) []byte {
	hasher := mimcCrypto.NewMiMC()
	_, err := hasher.Write(goConvertBalanceToBytes(account.Balance))
	if err != nil {
		panic(err)
	}
	balanceHash := hasher.Sum(nil)
	hasher.Reset()
	_, err = hasher.Write(account.UserId)
	if err != nil {
		panic(err)
	}
	_, err = hasher.Write(balanceHash)
	return hasher.Sum(nil)
}

// GoComputeMerkleRootFromAccounts computes the Merkle root from a list of accounts.
// It returns a consistent result with computeMerkleRootFromAccounts in the circuit.
func GoComputeMerkleRootFromAccounts(accounts []GoAccount) (rootHash []byte) {
	hashes := make([]Hash, len(accounts))
	for i, account := range accounts {
		hashes[i] = GoComputeMiMCHashForAccount(account)
	}
	return GoComputeMerkleRootFromHashes(hashes)
}

type Hash = []byte

// GoComputeMerkleRootFromHashes computes the MiMC Merkle root from a list of hashes.
func GoComputeMerkleRootFromHashes(hashes []Hash) (rootHash []byte) {
	if len(hashes) > 1024 {
		panic("number of hashes exceeds the maximum number of leaves in the Merkle tree")
	}

	hasher := mimcCrypto.NewMiMC()
	nodes := make([][]byte, PowOfTwo(TreeDepth))
	for i := 0; i < PowOfTwo(TreeDepth); i++ {
		if i < len(hashes) {
			nodes[i] = hashes[i]
		} else {
			nodes[i] = padToModBytes([]byte{}, false)
		}
	}
	for i := TreeDepth - 1; i >= 0; i-- {
		for j := 0; j < PowOfTwo(i); j++ {
			hasher.Reset()
			_, err := hasher.Write(nodes[j*2])
			if err != nil {
				panic(err)
			}
			_, err = hasher.Write(nodes[j*2+1])
			if err != nil {
				panic(err)
			}
			nodes[j] = hasher.Sum(nil)
		}
	}
	return nodes[0]
}

// ConvertGoBalanceToBalance converts a GoBalance to a Balance immediately before inclusion in the circuit.
func ConvertGoBalanceToBalance(goBalance GoBalance) Balance {
	return Balance{
		Bitcoin:  padToModBytes(goBalance.Bitcoin.Bytes(), goBalance.Bitcoin.Sign() == -1),
		Ethereum: padToModBytes(goBalance.Ethereum.Bytes(), goBalance.Ethereum.Sign() == -1),
	}
}

// ConvertGoAccountToAccount converts a GoAccount to an Account immediately before inclusion in the circuit.
func convertGoAccountToAccount(goAccount GoAccount) Account {
	return Account{
		UserId:  new(big.Int).SetBytes(goAccount.UserId),
		Balance: ConvertGoBalanceToBalance(goAccount.Balance),
	}
}

func ConvertGoAccountsToAccounts(goAccounts []GoAccount) (accounts []Account) {
	accounts = make([]Account, len(goAccounts))
	for i, goAccount := range goAccounts {
		accounts[i] = convertGoAccountToAccount(goAccount)
	}
	return accounts
}

// SumGoAccountBalancesIncludingNegatives sums the balances of a list of GoAccounts, including negative balances.
// Since we cannot use negative balances in the circuit, this function is only used for testing purposes.
func SumGoAccountBalancesIncludingNegatives(accounts []GoAccount) GoBalance {
	assetSum := GoBalance{Bitcoin: *big.NewInt(0), Ethereum: *big.NewInt(0)}
	for _, account := range accounts {
		b := make([]byte, 0)
		b = append(b, padToModBytes(account.Balance.Bitcoin.Bytes(), account.Balance.Bitcoin.Sign() == -1)...)
		assetSum.Bitcoin.Add(&assetSum.Bitcoin, new(big.Int).SetBytes(b))

		b = make([]byte, 0)
		b = append(b, padToModBytes(account.Balance.Ethereum.Bytes(), account.Balance.Ethereum.Sign() == -1)...)
		assetSum.Ethereum.Add(&assetSum.Ethereum, new(big.Int).SetBytes(b))
	}
	return assetSum
}

// SumGoAccountBalances sums the balances of a list of GoAccounts and panics on negative functions.
// This panic is because any circuit that is passed negative balances will violate constraints.
func SumGoAccountBalances(accounts []GoAccount) GoBalance {
	assetSum := GoBalance{Bitcoin: *big.NewInt(0), Ethereum: *big.NewInt(0)}
	for _, account := range accounts {
		if account.Balance.Bitcoin.Sign() == -1 || account.Balance.Ethereum.Sign() == -1 {
			panic("use SumGoAccountBalancesIncludingNegatives for negative balances")
		}
		assetSum.Bitcoin.Add(&assetSum.Bitcoin, &account.Balance.Bitcoin)
		assetSum.Ethereum.Add(&assetSum.Ethereum, &account.Balance.Ethereum)
	}
	return assetSum
}

// GenerateTestData generates test data for a given number of accounts with a seed based on the account index.
// Each account gets a random user ID.
func GenerateTestData(count int, seed int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {
	for i := 0; i < count; i++ {
		iWithSeed := (i + seed) * (seed + 1)
		btcCount, ethCount := int64(iWithSeed+45*iWithSeed+39), int64(iWithSeed*2+iWithSeed+1001)

		// Generate random user ID (16 bytes)
		userID := make([]byte, 16)
		_, err := rand.Read(userID)
		if err != nil {
			// Fallback to deterministic ID if random generation fails
			userID = []byte(fmt.Sprintf("user_%d_%d", i, seed))
		}

		accounts = append(accounts, GoAccount{UserId: userID, Balance: GoBalance{Bitcoin: *big.NewInt(btcCount), Ethereum: *big.NewInt(ethCount)}})
	}
	goAccountBalanceSum := SumGoAccountBalances(accounts)
	merkleRoot = GoComputeMerkleRootFromAccounts(accounts)
	merkleRootWithAssetSumHash = GoComputeMiMCHashForAccount(GoAccount{UserId: merkleRoot, Balance: goAccountBalanceSum})
	return accounts, goAccountBalanceSum, merkleRoot, merkleRootWithAssetSumHash
}

func (GoBalance *GoBalance) Equals(other GoBalance) bool {
	return GoBalance.Bitcoin.Cmp(&other.Bitcoin) == 0 && GoBalance.Ethereum.Cmp(&other.Ethereum) == 0
}
