package circuit

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/test"
)

func TestPadToModBytes(t *testing.T) {
	tests := []struct {
		name        string
		input       *big.Int
		expected    []byte
		shouldPanic bool
	}{
		{
			name:        "Zero value",
			input:       big.NewInt(0),
			expected:    make([]byte, 32), // ModBytes is 32, all zeros
			shouldPanic: false,
		},
		{
			name:        "Regular number",
			input:       big.NewInt(123456),
			expected:    append(make([]byte, 29), []byte{0x01, 0xe2, 0x40}...), // 123456 in big-endian bytes, padded to 32 bytes
			shouldPanic: false,
		},
		{
			name:        "Negative number",
			input:       big.NewInt(-5),
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("padToModBytes should have panicked with negative value")
					}
				}()
			}

			result := padToModBytes(tt.input)

			if tt.shouldPanic {
				t.Errorf("padToModBytes should have panicked")
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("padToModBytes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestGoComputeMiMCHashesForAccounts(t *testing.T) {
	assert := test.NewAssert(t)
	accounts := []GoAccount{
		{UserId: []byte{1, 2}, Balance: ConstructGoBalance(big.NewInt(1000000000), big.NewInt(11111))},
		{UserId: []byte{1, 3}, Balance: ConstructGoBalance(big.NewInt(0), big.NewInt(22222))},
	}

	expectedHashes := []Hash{
		{0x1, 0x8a, 0x24, 0xf9, 0x77, 0x3a, 0xaf, 0x74, 0x41, 0x1d, 0x2d, 0x6b, 0x4f, 0xc0, 0xe8, 0xc1, 0x3, 0x7, 0xd3, 0x84, 0x34, 0xf8, 0xf, 0x77, 0xa0, 0x55, 0x7, 0xf8, 0xee, 0xc4, 0xa, 0xb1},
		{0x25, 0x4d, 0x52, 0xf9, 0x5d, 0x98, 0x4c, 0x35, 0x43, 0xd0, 0xab, 0xff, 0x7d, 0xb1, 0xf, 0x19, 0x3b, 0xa6, 0x53, 0xab, 0x22, 0xe7, 0x1, 0xe4, 0x44, 0x52, 0x11, 0x45, 0xfc, 0x53, 0xbc, 0xcd},
	}

	actualHashes := GoComputeMiMCHashesForAccounts(accounts)

	for i, leaf := range actualHashes {
		assert.Equal(expectedHashes[i], leaf, "Account leaves should match")
	}
}

func TestGoComputeMerkleRoot(t *testing.T) {
	// some helper funcs to construct test cases:
	constructHashSlice := func(nums ...int64) []Hash {
		res := make([]Hash, len(nums))
		for i, num := range nums {
			res[i] = padToModBytes(big.NewInt(num))
		}
		return res
	}

	hashTwoNodes := func(hasher hash.StateStorer, hash1, hash2 Hash) Hash {
		hash, err := GoComputeHashOfTwoNodes(hasher, hash1, hash2, "node1", "node2")
		if err != nil {
			panic(err)
		}
		return hash
	}

	// test cases:
	tests := []struct {
		name         string
		hashes       []Hash
		depth        int
		expected     Hash
		shouldPanic  bool
		panicMessage string
	}{
		{
			name:   "Single hash",
			hashes: constructHashSlice(123),
			depth:  0,
			expected: func() Hash {
				return padToModBytes(big.NewInt(123))
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:   "Full tree of depth 2",
			hashes: constructHashSlice(123, 345, 567, 789),
			depth:  2,
			expected: func() Hash {
				hashes := constructHashSlice(123, 345, 567, 789)
				hasher := mimc.NewMiMC()
				return hashTwoNodes(hasher, hashTwoNodes(hasher, hashes[0], hashes[1]), hashTwoNodes(hasher, hashes[2], hashes[3]))
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:   "Partial list of hashes, tree depth 2",
			hashes: constructHashSlice(123, 234),
			depth:  2,
			expected: func() Hash {
				hashes := constructHashSlice(123, 234)
				hasher := mimc.NewMiMC()
				return hashTwoNodes(hasher, hashTwoNodes(hasher, hashes[0], hashes[1]), hashTwoNodes(hasher, padToModBytes(big.NewInt(0)), padToModBytes(big.NewInt(0))))
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:         "Too many leaves, tree depth 2",
			hashes:       constructHashSlice(123, 345, 452, 234, 123),
			depth:        2,
			expected:     []byte{0}, // doesn't matter cause should panic
			shouldPanic:  true,
			panicMessage: MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE,
		},
		{
			name:         "Invalid (negative) depth",
			hashes:       constructHashSlice(123),
			depth:        -1,
			expected:     []byte{0},
			shouldPanic:  true,
			panicMessage: "tree depth must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("goComputeMerkleRootFromHashes should have panicked.")
					} else if msg, ok := r.(string); !ok || msg != tt.panicMessage {
						t.Errorf("Expected panic with message '%v', got: %v", tt.panicMessage, r)
					}
				}()
			}

			result := goComputeMerkleRootFromHashes(tt.hashes, tt.depth)

			if tt.shouldPanic {
				t.Errorf("goComputeMerkleRootFromHashes should have panicked")
				return
			}

			if !bytes.Equal(result, tt.expected) {
				t.Errorf("goComputeMerkleRootFromHashes() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestPublicComputeMerkleRootMaxAccountsConstraint(t *testing.T) {
	// test that more than ACCOUNTS_PER_BATCH accounts causes a panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic with more than ACCOUNTS_PER_BATCH accounts")
		} else if msg, ok := r.(string); !ok || msg != MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE {
			t.Errorf("Expected panic with message '%v', got: %v", MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE, r)
		}
	}()

	// create ACCOUNTS_PER_BATCH + 1 accounts (exceeds max)
	accounts := make([]GoAccount, ACCOUNTS_PER_BATCH+1)
	for i := range accounts {
		accounts[i] = GoAccount{
			UserId:  []byte{byte(i % 256)},
			Balance: ConstructGoBalance(big.NewInt(1), big.NewInt(1)),
		}
	}

	// this should panic
	GoComputeMerkleRootFromAccounts(accounts)
}

func TestGoComputeMerkleTreeNodesFromHashes(t *testing.T) {
	// some helper funcs to construct test cases:
	constructHashSlice := func(nums ...int64) []Hash {
		res := make([]Hash, len(nums))
		for i, num := range nums {
			res[i] = padToModBytes(big.NewInt(num))
		}
		return res
	}

	hashTwoNodes := func(hasher hash.StateStorer, hash1, hash2 Hash) Hash {
		hash, err := GoComputeHashOfTwoNodes(hasher, hash1, hash2, "node1", "node2")
		if err != nil {
			panic(err)
		}
		return hash
	}

	// test cases:
	tests := []struct {
		name         string
		hashes       []Hash
		depth        int
		expected     [][]Hash
		shouldPanic  bool
		panicMessage string
	}{
		{
			name:   "single hash",
			hashes: constructHashSlice(123),
			depth:  0,
			expected: func() [][]Hash {
				return [][]Hash{{padToModBytes(big.NewInt(123))}}
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:   "full tree of depth 2",
			hashes: constructHashSlice(123, 345, 567, 789),
			depth:  2,
			expected: func() [][]Hash {
				hasher := mimc.NewMiMC()

				level2 := constructHashSlice(123, 345, 567, 789)
				level1 := []Hash{hashTwoNodes(hasher, level2[0], level2[1]), hashTwoNodes(hasher, level2[2], level2[3])}

				return [][]Hash{
					{hashTwoNodes(hasher, level1[0], level1[1])},
					level1,
					level2,
				}
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:   "partial list of hashes, tree depth 2",
			hashes: constructHashSlice(123, 234),
			depth:  2,
			expected: func() [][]Hash {
				hasher := mimc.NewMiMC()

				level2 := constructHashSlice(123, 234, 0, 0)
				level1 := []Hash{hashTwoNodes(hasher, level2[0], level2[1]), hashTwoNodes(hasher, level2[2], level2[3])}

				return [][]Hash{
					{hashTwoNodes(hasher, level1[0], level1[1])},
					level1,
					level2,
				}
			}(),
			shouldPanic:  false,
			panicMessage: "",
		},
		{
			name:         "too many leaves, tree depth 2",
			hashes:       constructHashSlice(123, 345, 452, 234, 123),
			depth:        2,
			expected:     [][]Hash{}, // doesn't matter cause should panic
			shouldPanic:  true,
			panicMessage: MERKLE_TREE_LEAF_LIMIT_EXCEEDED_MESSAGE,
		},
		{
			name:         "invalid (negative) depth",
			hashes:       constructHashSlice(123),
			depth:        -1,
			expected:     [][]Hash{},
			shouldPanic:  true,
			panicMessage: "tree depth must be greater than 0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("goComputeMerkleRootFromHashes should have panicked.")
					} else if msg, ok := r.(string); !ok || msg != tt.panicMessage {
						t.Errorf("expected panic with message '%v', got: %v", tt.panicMessage, r)
					}
				}()
			}

			result := goComputeMerkleTreeNodesFromHashes(tt.hashes, tt.depth)

			if tt.shouldPanic {
				t.Errorf("goComputeMerkleRootFromHashes should have panicked")
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("number of levels mismatch: got %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if len(result[i]) != len(tt.expected[i]) {
					t.Errorf("level %d: number of nodes mismatch: got %d, want %d", i, len(result[i]), len(tt.expected[i]))
					continue
				}
				for j := range result[i] {
					if !bytes.Equal(result[i][j], tt.expected[i][j]) {
						t.Errorf("mismatch at level %d, node %d: got %v, want %v", i, j, result[i][j], tt.expected[i][j])
					}
				}
			}
		})
	}
}

func TestComputeMerklePath(t *testing.T) {
	// some helper funcs to construct test cases:
	constructHashSlice := func(nums ...int64) []Hash {
		res := make([]Hash, len(nums))
		for i, num := range nums {
			res[i] = padToModBytes(big.NewInt(num))
		}
		return res
	}

	// test cases:
	tests := []struct {
		name        string
		position    int
		nodes       [][]Hash
		expected    []Hash
		shouldPanic bool
	}{
		{
			name:        "single node",
			position:    0,
			nodes:       [][]Hash{constructHashSlice(123)},
			expected:    []Hash{},
			shouldPanic: false,
		},
		{
			name:        "nodes of tree with depth 2",
			position:    3,
			nodes:       [][]Hash{constructHashSlice(192), constructHashSlice(532, 582), constructHashSlice(123, 432, 134, 532)},
			expected:    constructHashSlice(134, 532),
			shouldPanic: false,
		},
		{
			name:        "positive position out of bounds",
			position:    2,
			nodes:       [][]Hash{constructHashSlice(123)},
			expected:    []Hash{},
			shouldPanic: true,
		},
		{
			name:        "negative position out of bounds",
			position:    -1,
			nodes:       [][]Hash{constructHashSlice(123)},
			expected:    []Hash{},
			shouldPanic: true,
		},
		{
			name:        "invalid merkle nodes structure",
			position:    0,
			nodes:       [][]Hash{constructHashSlice(123), constructHashSlice(234)},
			expected:    []Hash{},
			shouldPanic: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("ComputeMerklePath should have panicked.")
					}
				}()
			}

			result := ComputeMerklePath(tt.position, tt.nodes)

			if tt.shouldPanic {
				t.Errorf("ComputeMerklePath should have panicked")
				return
			}

			if len(result) != len(tt.expected) {
				t.Errorf("number of hashes mismatch: got %d, want %d", len(result), len(tt.expected))
				return
			}
			for i := range result {
				if !bytes.Equal(result[i], tt.expected[i]) {
					t.Errorf("mismatch at node %d: got %v, want %v", i, result[i], tt.expected[i])
				}
			}
		})
	}
}

func TestSumGoAccountBalances(t *testing.T) {
	tests := []struct {
		name        string
		accounts    []GoAccount
		expected    GoBalance
		shouldPanic bool
	}{
		{
			name: "All positive balances",
			accounts: []GoAccount{
				{
					UserId:  []byte("user1"),
					Balance: ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
				},
				{
					UserId:  []byte("user2"),
					Balance: ConstructGoBalance(big.NewInt(150), big.NewInt(250)),
				},
			},
			expected:    ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			shouldPanic: false,
		},
		{
			name: "With negative balance for first asset",
			accounts: []GoAccount{
				{
					UserId:  []byte("user1"),
					Balance: ConstructGoBalance(big.NewInt(-250), big.NewInt(450)),
				},
			},
			expected:    GoBalance{}, // doesn't matter, should panic
			shouldPanic: true,
		},
		{
			name: "With negative balance for second asset",
			accounts: []GoAccount{
				{
					UserId:  []byte("user1"),
					Balance: ConstructGoBalance(big.NewInt(250), big.NewInt(-450)),
				},
			},
			expected:    GoBalance{}, // doesn't matter, should panic
			shouldPanic: true,
		},
		{
			name: "Zero balances",
			accounts: []GoAccount{
				{
					UserId:  []byte("user1"),
					Balance: ConstructGoBalance(),
				},
			},
			expected:    ConstructGoBalance(),
			shouldPanic: false,
		},
		{
			name:        "Empty account list",
			accounts:    []GoAccount{},
			expected:    ConstructGoBalance(),
			shouldPanic: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("SumGoAccountBalances should have panicked with negative balances")
					}
				}()
			}

			result := SumGoAccountBalances(tt.accounts)

			if tt.shouldPanic {
				t.Errorf("SumGoAccountBalances should have panicked")
				return
			}

			if !result.Equals(tt.expected) {
				t.Errorf("SumGoAccountBalances() = %v, want %v",
					result, tt.expected)
			}
		})
	}
}

func TestGoBalanceEquals(t *testing.T) {
	tests := []struct {
		name     string
		balance1 GoBalance
		balance2 GoBalance
		expected bool
	}{
		{
			name:     "Equal balances",
			balance1: ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			balance2: ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			expected: true,
		},
		{
			name:     "Different first asset",
			balance1: ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			balance2: ConstructGoBalance(big.NewInt(200), big.NewInt(450)),
			expected: false,
		},
		{
			name:     "Different second asset",
			balance1: ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			balance2: ConstructGoBalance(big.NewInt(250), big.NewInt(400)),
			expected: false,
		},
		{
			name:     "Zero values",
			balance1: ConstructGoBalance(),
			balance2: ConstructGoBalance(),
			expected: true,
		},
		{
			name:     "Positive vs negative",
			balance1: ConstructGoBalance(big.NewInt(250), big.NewInt(450)),
			balance2: ConstructGoBalance(big.NewInt(-250), big.NewInt(450)),
			expected: false,
		},
		{
			name:     "Large numbers",
			balance1: ConstructGoBalance(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))),
			balance2: ConstructGoBalance(new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))),
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.balance1.Equals(tt.balance2)

			if result != tt.expected {
				t.Errorf("GoBalance.Equals() = %v, want %v", result, tt.expected)
			}

			// test symmetry
			result = tt.balance2.Equals(tt.balance1)
			if result != tt.expected {
				t.Errorf("GoBalance.Equals() is not symmetric: %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestConvertRawUserIdToBytes(t *testing.T) {
	t.Run("basic alphanumeric conversion", func(t *testing.T) {
		userId := "user123"
		result := convertRawUserIdToBytes(userId)

		// Convert back to string to verify
		n := new(big.Int).SetBytes(result)
		resultBase36 := n.Text(36)

		if resultBase36 != userId {
			t.Errorf("Expected %s, got %s", userId, resultBase36)
		}
	})

	t.Run("hyphenated userId", func(t *testing.T) {
		userId := "user-123-456"
		expectedCleanId := "user123456" // hyphens removed
		result := convertRawUserIdToBytes(userId)

		// Convert back to string to verify
		n := new(big.Int).SetBytes(result)
		resultBase36 := n.Text(36)

		if resultBase36 != expectedCleanId {
			t.Errorf("Expected %s, got %s", expectedCleanId, resultBase36)
		}
	})

	t.Run("invalid characters", func(t *testing.T) {
		userId := "user@123"
		defer func() {
			if r := recover(); r == nil {
				t.Errorf("Expected panic with invalid characters")
			}
		}()
		convertRawUserIdToBytes(userId)
	})
}

func TestConvertRawGoAccountToGoAccount(t *testing.T) {
	t.Run("standard conversion with alphanumeric and hyphenated userId", func(t *testing.T) {
		rawAccount := RawGoAccount{
			UserId:  "user-123-abc",
			Balance: ConstructGoBalance(big.NewInt(1000), big.NewInt(2000)),
		}

		result := ConvertRawGoAccountToGoAccount(rawAccount)

		// Verify userId is converted correctly
		expectedUserId := convertRawUserIdToBytes("user-123-abc")
		if !bytes.Equal(expectedUserId, result.UserId) {
			t.Errorf("UserId not converted correctly")
		}

		// Verify balance remains unchanged
		if !result.Balance.Equals(rawAccount.Balance) {
			t.Errorf("Balance should remain unchanged")
		}
	})
}

func TestConvertGoAccountToRawGoAccount(t *testing.T) {
	t.Run("standard conversion", func(t *testing.T) {
		// Create a GoAccount
		userId := convertRawUserIdToBytes("user123")
		goAccount := GoAccount{
			UserId:  userId,
			Balance: ConstructGoBalance(big.NewInt(1000), big.NewInt(2000)),
		}

		// Convert to RawGoAccount
		result := ConvertGoAccountToRawGoAccount(goAccount)

		// Verify userId is in base36 format
		if result.UserId != "user123" {
			t.Errorf("Expected userId user123, got %s", result.UserId)
		}

		// Verify balance remains unchanged
		if !result.Balance.Equals(goAccount.Balance) {
			t.Errorf("Balance should remain unchanged")
		}
	})

	t.Run("round trip conversion", func(t *testing.T) {
		// Start with a GoAccount
		originalUserId := convertRawUserIdToBytes("test456abc")
		originalAccount := GoAccount{
			UserId:  originalUserId,
			Balance: ConstructGoBalance(big.NewInt(500), big.NewInt(600)),
		}

		// Convert to RawGoAccount and back
		rawAccount := ConvertGoAccountToRawGoAccount(originalAccount)
		reconvertedAccount := ConvertRawGoAccountToGoAccount(rawAccount)

		// Verify the round trip preserves the data
		if !bytes.Equal(originalAccount.UserId, reconvertedAccount.UserId) {
			t.Errorf("UserId should be preserved in round trip")
		}
		if !originalAccount.Balance.Equals(reconvertedAccount.Balance) {
			t.Errorf("Balance should be preserved in round trip")
		}
	})
}

func TestBatchConversionFunctions(t *testing.T) {
	t.Run("ConvertRawGoAccountsToGoAccounts", func(t *testing.T) {
		// Create a batch of raw accounts
		rawAccounts := []RawGoAccount{
			{
				UserId:  "user1",
				Balance: ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
			},
			{
				UserId:  "user-2",
				Balance: ConstructGoBalance(big.NewInt(300), big.NewInt(400)),
			},
		}

		// Convert to GoAccounts
		result := ConvertRawGoAccountsToGoAccounts(rawAccounts)

		// Verify conversion
		if len(result) != len(rawAccounts) {
			t.Errorf("Expected %d accounts, got %d", len(rawAccounts), len(result))
		}

		// Check first account
		expectedUserId1 := convertRawUserIdToBytes("user1")
		if !bytes.Equal(expectedUserId1, result[0].UserId) {
			t.Errorf("First account UserId not converted correctly")
		}
		if !result[0].Balance.Equals(rawAccounts[0].Balance) {
			t.Errorf("First account Balance should remain unchanged")
		}

		// Check second account
		expectedUserId2 := convertRawUserIdToBytes("user-2")
		if !bytes.Equal(expectedUserId2, result[1].UserId) {
			t.Errorf("Second account UserId not converted correctly")
		}
		if !result[1].Balance.Equals(rawAccounts[1].Balance) {
			t.Errorf("Second account Balance should remain unchanged")
		}
	})

	t.Run("ConvertGoAccountsToRawGoAccounts", func(t *testing.T) {
		// Create a batch of go accounts
		accounts := []GoAccount{
			{
				UserId:  convertRawUserIdToBytes("user1"),
				Balance: ConstructGoBalance(big.NewInt(100), big.NewInt(200)),
			},
			{
				UserId:  convertRawUserIdToBytes("user2"),
				Balance: ConstructGoBalance(big.NewInt(300), big.NewInt(400)),
			},
		}

		// Convert to RawGoAccounts
		result := ConvertGoAccountsToRawGoAccounts(accounts)

		// Verify conversion
		if len(result) != len(accounts) {
			t.Errorf("Expected %d accounts, got %d", len(accounts), len(result))
		}

		// Check first account
		if result[0].UserId != "user1" {
			t.Errorf("Expected user1, got %s", result[0].UserId)
		}
		if !result[0].Balance.Equals(accounts[0].Balance) {
			t.Errorf("First account Balance should remain unchanged")
		}

		// Check second account
		if result[1].UserId != "user2" {
			t.Errorf("Expected user2, got %s", result[1].UserId)
		}
		if !result[1].Balance.Equals(accounts[1].Balance) {
			t.Errorf("Second account Balance should remain unchanged")
		}
	})
}

func TestConstructGoBalance(t *testing.T) {
	tests := []struct {
		name           string
		initialValues  []*big.Int
		expectedLength int
		expectedValues []*big.Int
	}{
		{
			name:           "No initial values",
			initialValues:  []*big.Int{},
			expectedLength: GetNumberOfAssets(),
			expectedValues: nil, // Will check that all values are zero
		},
		{
			name:           "Partial initial values",
			initialValues:  []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)},
			expectedLength: GetNumberOfAssets(),
			expectedValues: []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)},
		},
		{
			name:           "Exact number of assets",
			initialValues:  make([]*big.Int, GetNumberOfAssets()),
			expectedLength: GetNumberOfAssets(),
			expectedValues: nil, // Will check that all values match inputs
		},
	}

	// Initialize the third test case with incrementing values
	if len(tests[2].initialValues) > 0 {
		for i := range tests[2].initialValues {
			tests[2].initialValues[i] = big.NewInt(int64(i+1) * 100)
		}
		tests[2].expectedValues = tests[2].initialValues
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConstructGoBalance(tt.initialValues...)

			// Check length matches expected
			if len(result) != tt.expectedLength {
				t.Errorf("ConstructGoBalance() length = %v, want %v", len(result), tt.expectedLength)
			}

			// Check values match expected
			if tt.expectedValues != nil {
				// Check specified values
				for i, val := range tt.expectedValues {
					if result[i].Cmp(val) != 0 {
						t.Errorf("ConstructGoBalance() value at index %d = %v, want %v", i, result[i], val)
					}
				}

				// Check remaining values are zero
				for i := len(tt.expectedValues); i < len(result); i++ {
					if result[i].Cmp(big.NewInt(0)) != 0 {
						t.Errorf("ConstructGoBalance() value at index %d should be zero, got %v", i, result[i])
					}
				}
			} else {
				// Check all values are zero when no expected values are provided
				for i, val := range result {
					if i < len(tt.initialValues) {
						// Should match input value
						if val.Cmp(tt.initialValues[i]) != 0 {
							t.Errorf("ConstructGoBalance() value at index %d = %v, want %v", i, val, tt.initialValues[i])
						}
					} else {
						// Should be zero
						if val.Cmp(big.NewInt(0)) != 0 {
							t.Errorf("ConstructGoBalance() value at index %d should be zero, got %v", i, val)
						}
					}
				}
			}
		})
	}
}

func TestGoConvertBalanceToBytes(t *testing.T) {
	tests := []struct {
		name         string
		goBalance    GoBalance
		shouldPanic  bool
		panicMessage string
		expectedLen  int
	}{
		{
			name:         "Valid balance",
			goBalance:    ConstructGoBalance(big.NewInt(100), big.NewInt(200)), // Constructs with correct length
			shouldPanic:  false,
			panicMessage: "",
			expectedLen:  GetNumberOfAssets() * ModBytes, // Each asset gets padded to ModBytes
		},
		{
			name:         "Incorrect balance length",
			goBalance:    GoBalance{big.NewInt(100), big.NewInt(200)}, // Only 2 values, not matching GetNumberOfAssets()
			shouldPanic:  true,
			panicMessage: INVALID_BALANCE_LENGTH_MESSAGE,
			expectedLen:  0, // Not relevant due to panic
		},
		{
			name: "All zero values",
			goBalance: func() GoBalance {
				return ConstructGoBalance()
			}(),
			shouldPanic:  false,
			panicMessage: "",
			expectedLen:  GetNumberOfAssets() * ModBytes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.shouldPanic {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("goConvertBalanceToBytes should have panicked")
					} else if msg, ok := r.(string); !ok || msg != tt.panicMessage {
						t.Errorf("Expected panic with message '%v', got: %v", tt.panicMessage, r)
					}
				}()
			}

			result := goConvertBalanceToBytes(tt.goBalance)

			if tt.shouldPanic {
				t.Errorf("goConvertBalanceToBytes should have panicked")
				return
			}

			// Check the length of the resulting byte slice
			if len(result) != tt.expectedLen {
				t.Errorf("goConvertBalanceToBytes() output length = %v, want %v", len(result), tt.expectedLen)
			}

			// Check content - each asset's bytes should be in the result
			offset := 0
			for _, asset := range tt.goBalance {
				paddedBytes := padToModBytes(asset)
				assetBytes := result[offset : offset+ModBytes]

				if !bytes.Equal(paddedBytes, assetBytes) {
					t.Errorf("Asset bytes at offset %d do not match expected padded bytes", offset)
				}
				offset += ModBytes
			}
		})
	}
}
