package circuit

import (
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
