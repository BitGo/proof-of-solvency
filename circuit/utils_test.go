package circuit

import (
	"bytes"
	"math/big"
	"testing"
)

func TestMaxAccountsConstraint(t *testing.T) {
	// test that more than 1024 accounts causes a panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic with more than 1024 accounts")
		}
	}()

	// create 1025 accounts (exceeds max)
	accounts := make([]GoAccount, 1025)
	for i := 0; i < 1025; i++ {
		accounts[i] = GoAccount{
			UserId:  []byte{byte(i % 256)},
			Balance: ConstructGoBalance(big.NewInt(1), big.NewInt(1)),
		}
	}

	// this should panic
	GoComputeMerkleRootFromAccounts(accounts)
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
