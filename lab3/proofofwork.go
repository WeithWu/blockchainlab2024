package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"math/big"
)

var (
	maxNonce = math.MaxInt64
)

const targetBits = 8

// ProofOfWork represents a proof-of-work
type ProofOfWork struct {
	block  *Block
	target *big.Int
}

// NewProofOfWork builds and returns a ProofOfWork
func NewProofOfWork(b *Block) *ProofOfWork {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-targetBits))

	pow := &ProofOfWork{b, target}

	return pow
}

// IntToBytes converts an int64 to a byte slice
func IntToBytes(n int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	return buf
}

// Run performs a proof-of-work
func (pow *ProofOfWork) Run() (int64, []byte) {
	var hashInt big.Int
	var hash [32]byte

	for nonce := int64(0); nonce < math.MaxInt64; nonce++ {
		data := pow.getCurBlkHeader(nonce)
		hash = sha256.Sum256(data)
		hashInt.SetBytes(hash[:])
		if hashInt.Cmp(pow.target) == -1 {
			return nonce, hash[:]
		}
	}

	return 0, nil // Return default values if proof-of-work fails
}

// getCurBlkHeader generates the current block's header data
func (pow *ProofOfWork) getCurBlkHeader(nonce int64) []byte {
	data := bytes.Join(
		[][]byte{
			IntToBytes(int64(pow.block.Header.Version)),
			pow.block.Header.PrevBlockHash[:],
			pow.block.Header.MerkleRoot[:],
			IntToBytes(pow.block.Header.Timestamp),
			IntToBytes(targetBits),
			IntToBytes(nonce),
		},
		[]byte{},
	)
	return data
}

// Validate validates block's PoW
func (pow *ProofOfWork) Validate() bool {
	var hashInt big.Int
	data := pow.getCurBlkHeader(pow.block.Header.Nonce)
	hash := sha256.Sum256(data)
	hashInt.SetBytes(hash[:])
	return hashInt.Cmp(pow.target) == -1
}
