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
2) Navigate to the Assets > GoAccount tab and click on the "Download Liability Proofs" button to download the `accountproof.json` corresponding to the Go Account. (At this point, it can be verified that inside `AccountInfo` object inside the downloaded file, the `WalletId` field corresponds to the wallet address of the Go Account and the Balance list corresponds to the balance of the GoAccount for supported currencies.)
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

This system uses a multi-layer Merkle Tree architecture combined with zk-SNARK circuits to allow for parallelization during proof generation and O(logn) verification time (where n is the total number of client accounts). The current 3-layer implementation can support up to 1 billion accounts, but it is designed to be extensible with more layers (if needed) without changing any guarantees. The zk-SNARK circuits and merkle tree hashes are built using Gnark library (v0.12.0).

### Key Concepts

- **GoAccount**: Consists of a WalletId (walletId) and a Balance list for the wallet.
- **GoBalance**: Each element of the Balance list corresponds to the amount of a particular currency the account holds. The currency an element at a particular index correponds to is the currency that is given at that index in the `AssetSymbols` list located in `circuit/constants.go`. This type is also the same type used to represent asset sums at any layer in the merkle tree.

### 3-Layer Proof Construction

For n GoAccounts, the system creates a hierarchical proof structure:

#### Bottom Layer
The accounts are split into batches of 1024 each and a bottom-layer proof (zk-SNARK circuit) is constructed for each batch:
- **Private Inputs**: Up to 1024 GoAccounts.
- **Public Outputs**: 
    - Merkle root of the merkle tree of the hashes of the input GoAccounts.
    - Hash of (merkle root + sum of all balances in batch).

#### Middle Layer
Bottom-layer proofs are split into batches of 1024 each and a mid-layer proof is constructed for each batch:
- **Private Inputs**: Up to 1024 bottom-layer proofs of form: {bottom_merkle_root, bottom_asset_sum}.
- **Public Outputs**:
    - Merkle root of the merkle tree of the hashes of input bottom-layer proof structs.
    - Hash of (merkle root + sum of all balances in this subtree).

#### Top Layer
A top-layer proof is constructed for up to 1024 mid-layer proofs:
- **Private Inputs**: Up to 1024 mid-layer proofs of form: {middle_merkle_root, middle_asset_sum}.
- **Public Outputs**:
    - Merkle root of the merkle tree of the hashes of input mid-layer proof structs.
    - Hash of (merkle root + total liability sum).
    - Total liability sum.

## Proof Verification
Liability proof verification for a BitGo client with a Go Account works in the following manner.
### What does BitGo provide?
1) The user account's wallet address and balance at the time the liability proofs were generated.
2) The zk-SNARK proof for the bottom-layer tree, mid-layer tree, and top-layer tree corresponding to the account.
3) The merkle root of the bottom-layer, mid-layer, and top-layer tree.
4) The hash of (merkle root + total subtree balance sum) for the bottom-layer, mid-layer, and top-layer tree.
4) The merkle proof path for:
    - The user account in the bottom-layer tree
    - The bottom-layer proof in the mid-layer tree
    - The mid-layer proof in the top-layer tree
6) The total liability sum (published publicly).

### What can be verified?
The user can verify that the provided wallet address and balance for their Go Account is correct.
Then they can use the user verification tool provided by this repo to:
1) Verify the zk-SNARK proofs for the bottom-layer tree, mid-layer tree, and top-layer tree are valid. This proves:
    - Each tree had only positive, non-overflow balances in the leaf nodes.
    - The total subtree sum in hash (merkle root + total subtree balance sum) was properly calculated from the leaf-node balances.
2) Verify the merkle proof paths for account -> bottom-layer tree, bottom-layer tree -> mid-layer tree, and mid-layer tree -> top-layer tree are valid. This proves:
    - The account's balance was included in the bottom-layer tree sum.
    - The bottom-layer tree sum was included in the mid-layer tree sum.
    - The mid-layer tree sum was included in the top-layer tree sum.
3) Verify the hash of (provided top-layer tree merkle root + published total liability sum) matches the provided hash of (top-layer tree merkle root + top-layer tree total subtree sum). This proves the published total liability sum is the true sum of all accounts included in the 3-layer merkle tree.

### Validity of Published Total Liability Sum
Each successful verification of a client's Go Account attests to the following (informally):
1) Every client's Go Account has been included in at least one bottom-layer tree (since the arbitrary client was included).
2) Every bottom-layer tree containing Go Accounts was included in a mid-layer tree (since the arbitrary client was included, and is part of an arbitrary tree).
3) Every mid-layer tree containing Go Accounts is included in the top-layer tree (by the same logic as above).
4) Additional accounts, bottom-layer proofs, and mid-layer proofs will not lower the liability sum in a bottom-layer proof, mid-layer proof, or the top-layer proof, respectively.
5) Every account included in every bottom proof included in every mid-layer proof included in the top-layer proof sums to _t_, the total liability, where hash(top_merkle_root, t) == t_hash (proved by circuit).

From (1), (2), (3), and (5), we can conclude that every BitGo user's balances is included in _t_. 
From (4), we can conclude that _t_ is at least the sum of all included BitGo users' balances.

Therefore, we can conclude (informally) that _t_ is at least the sum of all BitGo user liabilities.