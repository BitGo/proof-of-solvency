# Proof of Solvency

## Overview

This repository is part of BitGo's proof of solvency implementation for Go Accounts, enabling clients to verify that their assets are fully backed. The repository contains code for generating liability proofs and verifying them through a multi-level merkle tree structure with zero-knowledge proofs.

[Note: BitGo website UI updates to view total liabilites and download liability proofs for Go Accounts are still underway.]

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

#### UserVerify

This is the command used by a client with a Go Account to verify their account balance was included in the total liabilities published by BitGo. Steps for verification for a Go Account:
1) Login to the BitGo website.
2) Navigate to the Assets > GoAccount tab and click on the "Download Liability Proofs" button to download the `accountproof.json` corresponding to the Go Account. (At this point, it can be verified that inside `AccountInfo` object inside the downloaded file, the `UserId` field corresponds to the wallet address of the Go Account and the Balance list corresponds to the balance of the GoAccount for supported currencies.)
3) Using the binary, run:
```bash
./bgproof userverify path/to/accountproof.json
```

This will verify:
1) The account balance was included in the asset sum of the bottom-layer proof.
2) The asset sum of the bottom-layer proof was included in the asset sum of the mid-layer proof provided.
3) The asset sum of the mid-layer proof was included in the asset sum of the top-layer proof provided.
4) The true asset sum of the top-layer proof matches the total liability sum published by BitGo.
5) The asset sums of the bottom, mid, and top-layer proofs did not include any negative or overflowing balances.

#### Prove

This generates proofs for accounts in the files `batch_0.json...batch_n.json` in `out/secret` and stores the proofs in `out/public`. Each batch data file can contain a maximum of 1024 accounts. Usage:

```bash
./bgproof prove [number of input data batches]
```

#### Verify

This command is used for complete verification of generated proofs. It assumes generated proofs are in `out/public` and the accounts batches used as input are in `out/secret`. It verifies:
1) Each bottom-layer, mid-layer, and top-layer proof in `out/public` can be verified by the circuit.
2) Each bottom-layer proof was included in an mid-layer proof and each mid-layer proof was included in the top-layer proof.
3) Each account in `out/secret` was included in a bottom-layer proof.
4) Each bottom proof has a valid set of merkle nodes (which can be later used to compute merkle paths for accounts).
This can be useful for checking that the proofs were correctly generated. Please note that filenames are fixed,
and that the number of mid-layer and top-layer proofs are determined by the number of lower layer proofs.

```bash
./bgproof verify [number of input lower level proofs]
```

#### Generate

This generates dummy account batches purely for testing and puts it in `out/secret`. Running this can be helpful for getting an idea of what the input files look like.

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
