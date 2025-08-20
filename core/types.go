package core

import (
	"bitgo.com/proof_of_reserves/circuit"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
)

// AccountLeaf is a []byte alias for readability.
type Hash = circuit.Hash

// PartialProof contains the results of compiling and setting up a circuit.
type PartialProof struct {
	pk groth16.ProvingKey
	vk groth16.VerifyingKey
	cs constraint.ConstraintSystem
}

// ProofElements is an input to the prover. It contains sensitive data and should not be published.
type ProofElements struct {
	Accounts []circuit.GoAccount
	// AssetSum is not optional, but marshalling fails if it is not a pointer.
	AssetSum                   *circuit.GoBalance
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
}

// RawProofElements is contains all the same items as ProofElements, except the accounts are RawGoAccounts
// should be used when writing to a json file or reading directly from a json file.
type RawProofElements struct {
	Accounts                   []circuit.RawGoAccount
	AssetSum                   *circuit.GoBalance
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
}

// CompletedProof is an output of the prover. It contains the proof, public data, and (optionally) the full list of merkle nodes (hashes).
// It can be published if it meets the following criteria:
//  1. If this is a top level proof, the MerklePath are set to nil, MerklePosition is 0, and AssetSum is properly defined.
//  2. If this is not a top level proof, the MerklePath and MerklePosition are properly defined, and AssetSum is nil.
//  3. The MerkleNode field has been set to nil (we don't want to publish all the hashes).
type CompletedProof struct {
	Proof                      string
	VerificationKey            string
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte

	// MerklePath, MerklePosition, MerkleNodes, AssetSum are optional, depending on the case.
	MerklePath     []Hash
	MerklePosition int
	MerkleNodes    [][]Hash
	AssetSum       *circuit.GoBalance
}

// RawCompletedProof is a raw version of CompletedProof that is read from and written to files.
type RawCompletedProof struct {
	Proof                      string
	VerificationKey            string
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
	MerklePath                 []Hash
	MerklePosition             int
	MerkleNodes                [][]Hash
	AssetSum                   *[]string
}

// Types for user verification elements:
type UserProofInfo struct {
	UserMerklePath     []Hash
	UserMerklePosition int
	BottomProof        CompletedProof
	MiddleProof        CompletedProof
	TopProof           CompletedProof
}

type UserVerificationElements struct {
	AccountInfo circuit.GoAccount
	ProofInfo   UserProofInfo
}

// Types for reading and writing raw user verification elements from/to files:
type RawUVBalance struct {
	Asset  string
	Amount string
}

type RawLowerLevelProof struct {
	Proof                      string
	VerificationKey            string
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
	MerklePosition             int
	MerklePath                 []Hash
}

type RawTopLevelProof struct {
	Proof                      string
	VerificationKey            string
	MerkleRoot                 []byte
	MerkleRootWithAssetSumHash []byte
	AssetSum                   *[]RawUVBalance
}

type RawUserProofInfo struct {
	UserMerklePath     []Hash
	UserMerklePosition int
	BottomProof        RawLowerLevelProof
	MiddleProof        RawLowerLevelProof
	TopProof           RawTopLevelProof
}

type RawUserAccountInfo struct {
	UserId  string
	Balance []RawUVBalance
}

type RawUserVerificationElements struct {
	AccountInfo RawUserAccountInfo
	ProofInfo   RawUserProofInfo
}
