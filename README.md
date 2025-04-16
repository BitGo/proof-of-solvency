# Proof of Solvency

**THIS IS A WORK IN PROGRESS**

## Overview

This is a multi-levelled proof of solvency implementation that enables O(log n) time verification of proofs. 
This system is implemented using Gnark v0.12.0.

## Usage

Build the binary using

```bash
make build
```

Then run the binary using

```bash
./bgproof --help
```

### Commands:

#### Userverify

Get four proof files from BitGo by hitting the following endpoint:

```
GET /api/v2/wallet/{walletId}/balances/proofs
```

Using the proof files provided by BitGo, run the following command:

```bash
./bgproof userverify path/to/useraccount.json path/to/bottomlevelproof.json path/to/midlevelproof.json path/to/toplevelproof.json
```

This is intended to be the main verification path, requiring O(log n) time to verify proof of solvency. This verification path verifies that
1) Your account was included in the bottom level proof you were provided
2) The bottom level proof you were provided was included in the mid level proof you were provided
3) The mid level proof you were provided was included in the top level proof you were provided
4) The top level proof you were provided matches the asset sum you were provided
5) The chain of proofs is valid (i.e., your account was included in the asset sum for the low level proof, 
the low level proof was included in the asset sum for the mid level proof, 
the mid level proof was included in the asset sum for the high level proof, and
there were no accounts with overflowing balances or negative balances included in any of the asset sums.

#### Prove

This generates proofs for accounts in the files `data_0.json...data_(i-1).json` in `out/secret` and stores the proofs in `out/public`. 
Each input data file can contain a maximum of 1024 accounts.

```bash
./bgproof prove [number of input data batches]
```

#### Verify

This is a complete verification, requiring every proof file and one account in `out/user/test_account.json`. 
This can be useful for checking that the proofs were correctly generated. Please note that these filenames are fixed,
and that the number of mid and top level proofs are determined by the number of lower level proofs.

```bash
./bgproof verify [number of input lower level proofs]
```

#### Generate

This generates dummy data purely for testing and puts it in `out/secret`. Running this can be helpful for getting an idea of what the input files look like.

```bash
./bgproof generate [number of data batches to generate] [accounts to include per batch]
```

## Architecture

This can be extended to arbitrary layers to preserve O(log n) verification time.

The explanations assume a 2 layer implementation. 

However, the actual implementation is currently 3 layers, leading to an upper limit of 1 billion accounts. This does not change the guarantees.

### Bottom layer: 

_(Private inputs)_ [hash(user1 + balance1), hash(user2 + balance2), ..., hash(user1023 + balance1023)] => **(Public outputs)** merkle_hash_1, hash(merkle_hash_1 + sum(balance1, ..., balance1023))

Repeat for user1024...user2047 to get merkle_hash_2, etc

### Top layer: 

_(Private inputs)_ [hash(merkle_hash_1 + sum(balance1, ..., balance1023)), hash(merkle_hash_2 + sum(balance1024, ..., balance2047)), ...] => **(Public outputs)** merkle_hash_top, hash(merkle_hash_top + sum(total_liability))

sum(total_liability) is also published

## Verifying Proofs

The following method can be generalized to an arbitrary numbers of layers.

Clients can verify the proof of liabilities for a 2 layered proof in the following manner:

BitGo provides:
1) A merkle path for the bottom layer
2) A merkle path for the top layer
3) A zk-snark proof for the bottom layer
4) A zk-snark proof for the top layer
5) The root hash of the top layer
6) The root hash of the bottom layer
7) The total liability sum of the top layer
8) The hash of (5) and the sum of liabilities of the bottom layer

The user knows their userId and account balance.

The user can verify the proof in the following manner:
- Compute their leaf hash w = hash(userId + balance)
- Using the merkle path (1), verify that their leaf hash w is included 
in the merkle tree of the bottom layer with merkle root equal to (6)
- Using the zk-snark proof (3), verify that x = hash(merkle_hash_n + sum(balanceN, ..., balanceN+1023))
is correctly computed from every balance in the bottom layer
- Using the merkle path (2), verify that x is included
in the merkle tree of the bottom layer with merkle root equal to (5)
- Using the zk-snark proof (4), verify that y = hash(merkle_hash_top + sum(total_liability))
- Using the root hash (5) and the total liability sum (7), verify that hash((5) + (7)) == (8)

#### This verifies the proof because (informally) we know that:

1) Every BitGo user has been included in at least one bottom layer proof (since the arbitrary client was included)
2) Every bottom layer proof containing BitGo users was included in the top layer proof (since the arbitrary client was included, and is part of an arbitrary proof)
3) Additional users will not lower the liability sum in a bottom layer proof, and additional bottom layer proofs will not lower the total liability in the top layer proof (proved by circuit)
4) Every bottom layer proof sums to some (private) _s_ such that hash(p_root, s) == p_hash (proved by circuit)
5) Every bottom layer proof included in the top layer sums to _t_, the total liability, where hash(top_root, t) == t_hash (proved by circuit)

From (1), (2), (4), and (5), we can conclude that every BitGo user's balances is included in _t_. 
From (3), we can conclude that _t_ is at least the sum of all included BitGo users' balances.

Therefore, we can conclude that _t_ is at least the sum of all BitGo user liabilities.

**The actual implementation is a 3 layered proof to allow for a maximum of 1 billion accounts instead of 1 million with 2 layers. 
Refer to `core/verify.go` to see the actual implementation.**
