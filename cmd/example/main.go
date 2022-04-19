package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/douglasmakey/mktree"
)

type transaction struct {
	from  string
	to    string
	value string
}

func hashTrx(t transaction) []byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", t)))
	return h.Sum(nil)
}

func main() {
	trx1 := transaction{from: "mike", to: "bob", value: "100"}
	trx2 := transaction{from: "bob", to: "douglas", value: "250"}
	trx3 := transaction{from: "alice", to: "john", value: "100"}
	trx4 := transaction{from: "vitalik", to: "elon", value: "10000"}

	data := [][]byte{
		hashTrx(trx1),
		hashTrx(trx2),
		hashTrx(trx3),
		hashTrx(trx4),
	}

	// Create and verify the tree.
	t := mktree.NewFromHashes(data, mktree.DefaultShaHasher)
	fmt.Println("Hex: ", t.Root.Hex())

	// Getting the proof of the first transaction and verify it.
	proof, idxs, err := t.GetProof(hashTrx(trx1))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Verify proof of trx1: %+v \n", trx1)
	p := mktree.VerifyProof(t.Root.Hash, hashTrx(trx1), proof, idxs, mktree.DefaultShaHasher)
	fmt.Println("Proof integrity: ", p)

	// Change trx1 and try to verify it with the original proof.
	trx1.value = "1000"
	fmt.Printf("Verify proof of trx1: %+v \n", trx1)
	p = mktree.VerifyProof(t.Root.Hash, hashTrx(trx1), proof, idxs, mktree.DefaultShaHasher)
	fmt.Println("Proof integrity with a change trx: ", p)

	// Modifying the second transaction to send money to me.
	trx5 := transaction{from: "vitalik", to: "douglas", value: "10000"}
	t.Leaves[1].Hash = hashTrx(trx5)
	// We are going to verify the integrity of the tree after the modification
	fmt.Println("Tree integrity: ", t.Verify())
}
