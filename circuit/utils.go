package circuit

import (
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

type Hash = []byte

// ModBytes is needed to calculate the number of bytes needed to replicate hashing in the circuit.
var ModBytes = len(ecc.BN254.ScalarField().Bytes())

// AssetSymbols is an array storing symbols for cryptocurrencies (i.e. mapping indices to cryptocurrencies)
var AssetSymbols = []string{"ALGO", "ARBETH", "AVAXC", "AVAXP", "BTC", "BCH", "ADA", "CSPR", "TIA",
	"COREUM", "ATOM", "DASH", "DOGE", "EOS", "ETH", "ETC", "HBAR", "LTC", "NEAR",
	"OSMO", "DOT", "POLYGON", "SEI", "SOL", "STX", "XLM", "SUI", "TRX", "XRP",
	"ZEC", "ZETA", "BLD", "BSC", "TON", "COREDAO", "BERA", "TAO", "APT", "XDC", "WEMIX"}

// Getter function to interact with AssetSymbols array
// (created in case we retrieve AssetSymbols from different source in future)
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

// RawGoAccount represents an account read from file (with a string UserId). It can be converted to
// GoAccount (to manipulate here) through ConvertRawGoAccountToAccount.
type RawGoAccount struct {
	UserId  string
	Balance GoBalance
}

// padToModBytes returns the bytes of the input value padded to ModBytes length
func padToModBytes(num *big.Int) (paddedValue []byte) {
	// If the value is negative, it will fail the circuit range check (since the sign extended version
	// will be greater than 128 bytes, which is an overflow). So we simply panic here.
	if num.Sign() < 0 {
		panic("negative value cannot be used in the circuit")
	}

	value := num.Bytes()
	return append(make([]byte, ModBytes-len(value)), value...)
}

// goConvertBalanceToBytes converts a GoBalance to bytes.
func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	if len(balance) != GetNumberOfAssets() {
		panic(INVALID_BALANCE_LENGTH_MESSAGE)
	}

	value = make([]byte, 0)
	for _, asset := range balance {
		value = append(value, padToModBytes(asset)...)
	}
	return value
}

// GoComputeMiMCHashForAccount computes the MiMC hash of the account's balance and user ID
// and returns a consistent result with hashAccount in the circuit.
func GoComputeMiMCHashForAccount(account GoAccount) Hash {
	hasher := mimc.NewMiMC()

	// hash balances
	_, err := hasher.Write(goConvertBalanceToBytes(account.Balance))
	if err != nil {
		panic("Error writing GoBalance bytes to hasher: " + err.Error())
	}
	balanceHash := hasher.Sum(nil)

	// add userId to hasher
	hasher.Reset()
	_, err = hasher.Write(account.UserId)
	if err != nil {
		panic("Error writing UserId to hasher: " + err.Error())
	}

	// add balanceHash to hasher and return full hash
	_, err = hasher.Write(balanceHash)
	if err != nil {
		panic("Error writing GoBalance hash to hasher: " + err.Error())
	}
	return hasher.Sum(nil)
}

// GoComputeMiMCHashesForAccounts computes the MiMC hash of each account in accounts and returns
// them in a slice.
func GoComputeMiMCHashesForAccounts(accounts []GoAccount) (hashes []Hash) {
	hashes = make([]Hash, len(accounts))
	for i, account := range accounts {
		hashes[i] = GoComputeMiMCHashForAccount(account)
	}
	return hashes
}

// goComputeMerkleRootFromHashes computes the MiMC Merkle root from a list of hashes,
// given a particular TreeDepth.
func goComputeMerkleRootFromHashes(hashes []Hash, treeDepth int) (rootHash Hash) {
	// preliminary checks
	if treeDepth < 0 {
		panic("tree depth must be greater than 0")
	}
	if len(hashes) > powOfTwo(treeDepth) {
		panic(MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE)
	}

	// store hashes of accounts (pad with 0's to reach 2^treeDepth nodes)
	nodes := make([]Hash, powOfTwo(treeDepth))
	for i := 0; i < powOfTwo(treeDepth); i++ {
		if i < len(hashes) {
			nodes[i] = hashes[i]
		} else {
			nodes[i] = padToModBytes(big.NewInt(0))
		}
	}

	// iteratively calculate hashes of parent nodes from bottom level to root
	hasher := mimc.NewMiMC()
	for i := treeDepth - 1; i >= 0; i-- {
		for j := 0; j < powOfTwo(i); j++ {
			hasher.Reset()
			_, err := hasher.Write(nodes[j*2])
			if err != nil {
				panic("Error writing node " + strconv.Itoa(j*2) + " to hasher: " + err.Error())
			}
			_, err = hasher.Write(nodes[j*2+1])
			if err != nil {
				panic("Error writing node " + strconv.Itoa(j*2+1) + " to hasher: " + err.Error())
			}
			nodes[j] = hasher.Sum(nil)
		}
	}
	return nodes[0]
}

// GoComputeMerkleRootFromHashes computes the MiMC Merkle root from a list of hashes,
// assuming Merkle Tree of depth TreeDepth.
func GoComputeMerkleRootFromHashes(hashes []Hash) (rootHash Hash) {
	return goComputeMerkleRootFromHashes(hashes, TreeDepth)
}

// GoComputeMerkleRootFromAccounts computes the Merkle root from a list of accounts.
// It returns a consistent result with computeMerkleRootFromAccounts in the circuit.
func GoComputeMerkleRootFromAccounts(accounts []GoAccount) (rootHash Hash) {
	return GoComputeMerkleRootFromHashes(GoComputeMiMCHashesForAccounts(accounts))
}

func goComputeMerkleTreenodesFromHashes(hashes []Hash, treeDepth int) [][]Hash {
	// preliminary checks
	if treeDepth < 0 {
		panic("tree depth must be greater than 0")
	}
	if len(hashes) > powOfTwo(treeDepth) {
		panic(MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE)
	}

	// create [][]Hash to store all internal nodes
	// nodes[i] will represent the hashes of all the nodes at depth i
	nodes := make([][]Hash, treeDepth+1)

	// at bottom layer, store hashes of accounts (pad with 0's to reach 2^treeDepth nodes)
	nodes[0] = make([]Hash, powOfTwo(treeDepth))
	for i := 0; i < powOfTwo(treeDepth); i++ {
		if i < len(hashes) {
			nodes[treeDepth][i] = hashes[i]
		} else {
			nodes[treeDepth][i] = padToModBytes(big.NewInt(0))
		}
	}

	// iteratively calculate hashes of parent nodes from bottom level to root
	hasher := mimc.NewMiMC()
	for i := treeDepth - 1; i >= 0; i-- {
		nodes[i] = make([]Hash, powOfTwo(i))
		for j := 0; j < powOfTwo(i); j++ {
			hasher.Reset()
			_, err := hasher.Write(nodes[i+1][j*2])
			if err != nil {
				panic("Error writing node " + strconv.Itoa(j*2) + " to hasher: " + err.Error())
			}
			_, err = hasher.Write(nodes[i+1][j*2+1])
			if err != nil {
				panic("Error writing node " + strconv.Itoa(j*2+1) + " to hasher: " + err.Error())
			}
			nodes[i][j] = hasher.Sum(nil)
		}
	}
	return nodes
}

func GoComputeMerkleTreeNodesFromAccounts(accounts []GoAccount) [][]Hash {
	return goComputeMerkleTreenodesFromHashes(GoComputeMiMCHashesForAccounts(accounts), TreeDepth)
}

// ConvertGoBalanceToBalance converts a GoBalance to a Balance immediately before inclusion in the circuit.
func ConvertGoBalanceToBalance(goBalance GoBalance) Balance {
	if len(goBalance) != GetNumberOfAssets() {
		panic(INVALID_BALANCE_LENGTH_MESSAGE)
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

// Convert raw UserID string to a []byte by removing any hyphens, interpreting it as
// a base36 number, and then converting that number to a []byte. If this is used to
// get the GoAccount.UserId, the userId should not exceed BN254 curve limit as long
// as the string is less than 49 characters in length.
func convertRawUserIdToBytes(userId string) []byte {
	// remove any hyphens from user id
	cleanedUserId := strings.ReplaceAll(userId, "-", "")

	// convert to bytes (interpreted as a base36 string)
	n := new(big.Int)
	_, ok := n.SetString(cleanedUserId, 36)
	if !ok {
		panic("failed to convert userId to big.Int from base36: " + cleanedUserId)
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

// Util to construct GoBalance.
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

// SumGoAccountBalances sums the balances of a list of GoAccounts and panics on negative functions.
// This panic is because any circuit that is passed negative balances will violate constraints.
func SumGoAccountBalances(accounts []GoAccount) GoBalance {
	assetSum := ConstructGoBalance()
	for _, account := range accounts {
		if len(account.Balance) != GetNumberOfAssets() {
			panic(INVALID_BALANCE_LENGTH_MESSAGE)
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
func GenerateTestData(count int, seed int) (accounts []GoAccount, assetSum GoBalance, merkleRoot Hash, merkleRootWithAssetSumHash Hash) {

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

// Check if GoBalance equal to other.
func (GoBalance *GoBalance) Equals(other GoBalance) bool {
	if len(*GoBalance) != len(other) || len(*GoBalance) != GetNumberOfAssets() {
		panic(INVALID_BALANCE_LENGTH_MESSAGE)
	}

	for i := range *GoBalance {
		if (*GoBalance)[i].Cmp(other[i]) != 0 {
			return false
		}
	}
	return true
}
