package circuit

import (
	"fmt"
	"math/big"
	"math/rand"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// ModBytes is needed to calculate the number of bytes needed to replicate hashing in the circuit.
var ModBytes = len(ecc.BN254.ScalarField().Bytes())

// array storing symbols for cryptocurrencies (essentially mapping indices to cryptocurrencies)
var AssetSymbols = []string{"ALGO", "ARBETH", "AVAXC", "AVAXP", "BTC", "BCH", "ADA", "CSPR", "TIA",
	"COREUM", "ATOM", "DASH", "DOGE", "EOS", "ETH", "ETC", "HBAR", "LTC", "NEAR",
	"OSMO", "DOT", "POLYGON", "SEI", "SOL", "STX", "XLM", "SUI", "TRX", "XRP",
	"ZEC", "ZETA", "BLD", "BSC", "TON", "COREDAO", "BERA", "TAO", "APT", "XDC", "WEMIX"}

// Have these getter functions incase we decide to get asset symbols from a different source in the future
func GetNumberOfAssets() int {
	return len(AssetSymbols)
}

func GetAssetSymbols() []string {
	return AssetSymbols
}

// GoBalance represents the balance of an account. It can be converted to Balance for use in the circuit
// through ConvertGoBalanceToBalance.
type GoBalance []*big.Int

// GoAccount represents an account. It can be converted to Account for use in the circuit
// through ConvertGoAccountToAccount.
type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

type RawGoAccount struct {
	UserId  string
	Balance GoBalance
}

// padToModBytes pads the input value to ModBytes length. If the value is negative, it sign-extends the value.
func padToModBytes(num *big.Int) (paddedValue []byte) {
	value := num.Bytes()
	isNegative := num.Sign() < 0
	paddedValue = make([]byte, ModBytes-len(value))

	// If the value is negative, it will fail the circuit range check (since the sign extended version
	// will be greater than 64 bytes, which is an overflow). So we simple panic here.
	if isNegative {
		panic("negative value cannot be used in the circuit")
	}

	paddedValue = append(paddedValue, value...)
	return paddedValue
}

// goConvertBalanceToBytes converts a GoBalance to bytes in the same way as the circuit does.
func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	if len(balance) != GetNumberOfAssets() {
		panic("balance must have the same length as assets")
	}

	value = make([]byte, 0)
	for _, asset := range balance {
		value = append(value, padToModBytes(asset)...)
	}
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
			nodes[i] = padToModBytes(big.NewInt(0))
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
	if len(goBalance) != GetNumberOfAssets() {
		panic("balance must have the same length as assets")
	}

	balance := make(Balance, GetNumberOfAssets())
	for i, asset := range goBalance {
		balance[i] = padToModBytes(asset)
	}
	return balance
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

// Convert raw userId base36 string to a []byte properly (by first interpreting as a number)
// in this way, the GoAccount.UserId should not exceed BN254 curve limit as long as the string
// is less than 49 characters in length
func convertRawUserIdToBytes(userId string) []byte {
	// remove any hyphens from user id
	cleanedUserId := strings.ReplaceAll(userId, "-", "")

	// convert to bytes (interpreted as a base36 string)
	n := new(big.Int)
	_, ok := n.SetString(cleanedUserId, 36)
	if !ok {
		panic("Failed to convert userId to big.Int from base36: " + cleanedUserId)
	}
	return n.Bytes()
}

// Converts a RawGoAccount (read from json file) to a GoAccount
func ConvertRawGoAccountToGoAccount(rawAccount RawGoAccount) GoAccount {
	return GoAccount{
		UserId:  convertRawUserIdToBytes(rawAccount.UserId),
		Balance: rawAccount.Balance,
	}
}

// Converts a GoAccount to a RawGoAccount properly (for writing to json file)
func ConvertGoAccountToRawGoAccount(goAccount GoAccount) RawGoAccount {
	return RawGoAccount{
		UserId:  new(big.Int).SetBytes(goAccount.UserId).Text(36),
		Balance: goAccount.Balance,
	}
}

func ConvertRawGoAccountsToGoAccounts(rawAccounts []RawGoAccount) []GoAccount {
	accounts := make([]GoAccount, len(rawAccounts))
	for i, rawAccount := range rawAccounts {
		accounts[i] = ConvertRawGoAccountToGoAccount(rawAccount)
	}
	return accounts
}

func ConvertGoAccountsToRawGoAccounts(accounts []GoAccount) []RawGoAccount {
	rawAccounts := make([]RawGoAccount, len(accounts))
	for i, account := range accounts {
		rawAccounts[i] = ConvertGoAccountToRawGoAccount(account)
	}
	return rawAccounts
}

// SumGoAccountBalances sums the balances of a list of GoAccounts and panics on negative functions.
// This panic is because any circuit that is passed negative balances will violate constraints.
func SumGoAccountBalances(accounts []GoAccount) GoBalance {
	assetSum := make(GoBalance, GetNumberOfAssets())
	for i := range assetSum {
		assetSum[i] = big.NewInt(0)
	}

	for _, account := range accounts {
		if len(account.Balance) != GetNumberOfAssets() {
			panic("balance must have the same length as assets")
		}
		for i, asset := range account.Balance {
			if asset.Sign() == -1 {
				panic("negative asset balance found")
			}
			assetSum[i].Add(assetSum[i], asset)
		}
	}
	return assetSum
}

// GenerateTestData generates test data for a given number of accounts with a seed based on the account index.
// Each account gets a random user ID.
func GenerateTestData(count int, seed int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {

	// initialize random number generator with seed
	source := rand.NewSource(int64(seed))
	rng := rand.New(source)

	for i := 0; i < count; i++ {
		// generate random user ID
		userId := convertRawUserIdToBytes(fmt.Sprintf("user%d", rng.Int31()))

		// generate random balances between 0 and 10,500
		balances := make(GoBalance, GetNumberOfAssets())
		for i := range balances {
			balances[i] = big.NewInt(rng.Int63n(10500))
		}

		accounts = append(accounts, GoAccount{UserId: userId, Balance: balances})
	}
	goAccountBalanceSum := SumGoAccountBalances(accounts)
	merkleRoot = GoComputeMerkleRootFromAccounts(accounts)
	merkleRootWithAssetSumHash = GoComputeMiMCHashForAccount(GoAccount{UserId: merkleRoot, Balance: goAccountBalanceSum})
	return accounts, goAccountBalanceSum, merkleRoot, merkleRootWithAssetSumHash
}

func ConstructGoBalance(initialBalances ...*big.Int) GoBalance {
	balances := make(GoBalance, GetNumberOfAssets())
	for i := range balances {
		if i < len(initialBalances) {
			balances[i] = initialBalances[i]
		} else {
			balances[i] = big.NewInt(0)
		}
	}
	return balances
}

func (GoBalance *GoBalance) Equals(other GoBalance) bool {
	if len(*GoBalance) != len(other) || len(*GoBalance) != GetNumberOfAssets() {
		panic("balance must have the same length as assets")
	}

	for i := range *GoBalance {
		if (*GoBalance)[i].Cmp(other[i]) != 0 {
			return false
		}
	}
	return true
}
