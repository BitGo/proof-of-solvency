package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	mimcCrypto "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"math/big"
)

var ModBytes = len(ecc.BN254.ScalarField().Bytes())

type GoBalance struct {
	Bitcoin  big.Int
	Ethereum big.Int
}

type GoAccount struct {
	UserId  []byte
	Balance GoBalance
}

func goConvertBalanceToBytes(balance GoBalance) (value []byte) {
	value = make([]byte, 0)
	value = append(value, padToModBytes(balance.Bitcoin.Bytes(), balance.Bitcoin.Sign() == -1)...)
	value = append(value, padToModBytes(balance.Ethereum.Bytes(), balance.Ethereum.Sign() == -1)...)

	return value
}

func padToModBytes(value []byte, isNegative bool) (paddedValue []byte) {
	paddedValue = make([]byte, ModBytes-len(value))
	// sign extension
	if isNegative {
		for i := range paddedValue {
			paddedValue[i] = 0xFF
		}
		paddedValue[0] = 0x0F // this is 254 bits not 256
	}
	paddedValue = append(paddedValue, value...)
	return paddedValue
}

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

func GoComputeMerkleRootFromAccounts(accounts []GoAccount) (rootHash []byte) {
	hashes := make([]Hash, len(accounts))
	for i, account := range accounts {
		hashes[i] = GoComputeMiMCHashForAccount(account)
	}
	return GoComputeMerkleRootFromHashes(hashes)
}

type Hash = []byte

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

func ConvertGoBalanceToBalance(goBalance GoBalance) Balance {
	return Balance{
		Bitcoin:  padToModBytes(goBalance.Bitcoin.Bytes(), goBalance.Bitcoin.Sign() == -1),
		Ethereum: padToModBytes(goBalance.Ethereum.Bytes(), goBalance.Ethereum.Sign() == -1),
	}
}

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

// strictly for testing
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

func GenerateTestData(count int, seed int) (accounts []GoAccount, assetSum GoBalance, merkleRoot []byte, merkleRootWithAssetSumHash []byte) {
	for i := 0; i < count; i++ {
		iWithSeed := (i + seed) * (seed + 1)
		btcCount, ethCount := int64(iWithSeed+45*iWithSeed+39), int64(iWithSeed*2+iWithSeed+1001)
		accounts = append(accounts, GoAccount{UserId: []byte("foo"), Balance: GoBalance{Bitcoin: *big.NewInt(btcCount), Ethereum: *big.NewInt(ethCount)}})
	}
	goAccountBalanceSum := SumGoAccountBalances(accounts)
	merkleRoot = GoComputeMerkleRootFromAccounts(accounts)
	merkleRootWithAssetSumHash = GoComputeMiMCHashForAccount(GoAccount{UserId: merkleRoot, Balance: goAccountBalanceSum})
	return accounts, goAccountBalanceSum, merkleRoot, merkleRootWithAssetSumHash
}

func (GoBalance *GoBalance) Equals(other GoBalance) bool {
	return GoBalance.Bitcoin.Cmp(&other.Bitcoin) == 0 && GoBalance.Ethereum.Cmp(&other.Ethereum) == 0
}
