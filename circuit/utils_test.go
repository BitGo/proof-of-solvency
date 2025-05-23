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
			UserId: []byte{byte(i % 256)},
			Balance: GoBalance{
				Bitcoin:  *big.NewInt(1),
				Ethereum: *big.NewInt(1),
			},
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
					UserId: []byte("user1"),
					Balance: GoBalance{
						Bitcoin:  *big.NewInt(100),
						Ethereum: *big.NewInt(200),
					},
				},
				{
					UserId: []byte("user2"),
					Balance: GoBalance{
						Bitcoin:  *big.NewInt(150),
						Ethereum: *big.NewInt(250),
					},
				},
			},
			expected: GoBalance{
				Bitcoin:  *big.NewInt(250),
				Ethereum: *big.NewInt(450),
			},
			shouldPanic: false,
		},
		{
			name: "With negative Bitcoin balance",
			accounts: []GoAccount{
				{
					UserId: []byte("user1"),
					Balance: GoBalance{
						Bitcoin:  *big.NewInt(-100),
						Ethereum: *big.NewInt(200),
					},
				},
			},
			expected:    GoBalance{}, // doesn't matter, should panic
			shouldPanic: true,
		},
		{
			name: "With negative Ethereum balance",
			accounts: []GoAccount{
				{
					UserId: []byte("user1"),
					Balance: GoBalance{
						Bitcoin:  *big.NewInt(100),
						Ethereum: *big.NewInt(-200),
					},
				},
			},
			expected:    GoBalance{}, // doesn't matter, should panic
			shouldPanic: true,
		},
		{
			name: "Zero balances",
			accounts: []GoAccount{
				{
					UserId: []byte("user1"),
					Balance: GoBalance{
						Bitcoin:  *big.NewInt(0),
						Ethereum: *big.NewInt(0),
					},
				},
			},
			expected: GoBalance{
				Bitcoin:  *big.NewInt(0),
				Ethereum: *big.NewInt(0),
			},
			shouldPanic: false,
		},
		{
			name:     "Empty account list",
			accounts: []GoAccount{},
			expected: GoBalance{
				Bitcoin:  *big.NewInt(0),
				Ethereum: *big.NewInt(0),
			},
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
			name: "Equal balances",
			balance1: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(200),
			},
			balance2: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(200),
			},
			expected: true,
		},
		{
			name: "Different Bitcoin",
			balance1: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(200),
			},
			balance2: GoBalance{
				Bitcoin:  *big.NewInt(150),
				Ethereum: *big.NewInt(200),
			},
			expected: false,
		},
		{
			name: "Different Ethereum",
			balance1: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(200),
			},
			balance2: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(250),
			},
			expected: false,
		},
		{
			name: "Zero values",
			balance1: GoBalance{
				Bitcoin:  *big.NewInt(0),
				Ethereum: *big.NewInt(0),
			},
			balance2: GoBalance{
				Bitcoin:  *big.NewInt(0),
				Ethereum: *big.NewInt(0),
			},
			expected: true,
		},
		{
			name: "Positive vs negative",
			balance1: GoBalance{
				Bitcoin:  *big.NewInt(100),
				Ethereum: *big.NewInt(200),
			},
			balance2: GoBalance{
				Bitcoin:  *big.NewInt(-100),
				Ethereum: *big.NewInt(200),
			},
			expected: false,
		},
		{
			name: "Large numbers",
			balance1: GoBalance{
				Bitcoin:  *new(big.Int).SetUint64(^uint64(0)), // max uint64
				Ethereum: *new(big.Int).SetUint64(^uint64(0)),
			},
			balance2: GoBalance{
				Bitcoin:  *new(big.Int).SetUint64(^uint64(0)),
				Ethereum: *new(big.Int).SetUint64(^uint64(0)),
			},
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
