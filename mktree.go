package mktree

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
)

type Tree struct {
	Root   *Node
	Leaves []*Node
	h      Hasher
}

type Node struct {
	Parent *Node
	Left   *Node
	Right  *Node
	Hash   []byte
}

func (n *Node) Hex() string {
	return hex.EncodeToString(n.Hash)
}

type Hashable interface {
	io.Reader
}

// NewFromHashables creates a Merkle tree from hashables objects.
func NewFromHashables(hashables []Hashable, h Hasher) (*Tree, error) {
	t := &Tree{
		Leaves: make([]*Node, 0, len(hashables)),
		h:      h,
	}

	// Appends leaves nodes.
	for _, hashable := range hashables {
		h, err := t.h.Hashable(hashable)
		if err != nil {
			return nil, err
		}
		t.Leaves = append(t.Leaves, &Node{Hash: h})
	}

	t.Root = t.buildRoot()
	return t, nil
}

// NewFromHashes creates a Merkle tree from hashes.
func NewFromHashes(hashes [][]byte, h Hasher) *Tree {
	t := &Tree{
		Leaves: make([]*Node, 0, len(hashes)),
		h:      h,
	}

	// Add leaf nodes.
	for _, h := range hashes {
		t.Leaves = append(t.Leaves, &Node{Hash: h})
	}

	t.Root = t.buildRoot()
	return t
}

// VerifyProof verifies the integrity of the given value.
func VerifyProof(rootHash, value []byte, proofs [][]byte, idxs []int, h Hasher) bool {
	prevHash := value
	for i := 0; i < len(proofs); i++ {
		if idxs[i] == 0 {
			prevHash = h.Hash(proofs[i], prevHash)
		} else {
			prevHash = h.Hash(prevHash, proofs[i])
		}
	}

	return bytes.Equal(rootHash, prevHash)
}

// GetProof returns the Merkle path proof to verify the integrity of the given hash.
func (t *Tree) GetProof(hash []byte) ([][]byte, []int, error) {
	var (
		path [][]byte
		idxs []int
	)

	// Find the leaf node for the specific hash.
	for _, currentNode := range t.Leaves {
		if bytes.Equal(currentNode.Hash, hash) {
			// After finding the node, we will scale the tree using the relationship of the nodes to their parent nodes.
			parent := currentNode.Parent
			for parent != nil {
				// If the current node is the left child, we need the right child to calculate the parent hash
				// for the proof and vice versa.
				// i.e:
				// If CurrentNode == Left ; ParentHash = (CurrentNode.Hash, RightChild.Hash)
				// If CurrentNode == Right ; ParentHash = (LeftChild.Hash, CurrentNode.Hash)
				// So we have to add the corresponding hash to the path, and in idxs, we save the hash's position 0
				// for left and 1 for right. In this way, when we want to verify the proof, we can know if
				// the given hash is the left o right child.
				if bytes.Equal(currentNode.Hash, parent.Left.Hash) {
					path = append(path, parent.Right.Hash)
					idxs = append(idxs, 1)
				} else {
					path = append(path, parent.Left.Hash)
					idxs = append(idxs, 0)
				}
				currentNode = parent
				parent = currentNode.Parent
			}
			return path, idxs, nil
		}
	}
	return path, idxs, errors.New("hash does not belong to the tree")
}

// Verify rebuild the tree to verify its integrity.
func (t *Tree) Verify() bool {
	if len(t.Leaves) == 0 || t.Root == nil {
		return false
	}

	cr := t.buildRoot()
	return bytes.Equal(t.Root.Hash, cr.Hash)
}

func (t *Tree) buildRoot() *Node {
	nodes := t.Leaves
	// We are iterating until we reach a single node, which will be our root.
	for len(nodes) > 1 {
		var parents []*Node

		// Having an odd number of nodes at this level, we will duplicate the last node to concatenate it with itself.
		if len(nodes)%2 != 0 {
			nodes = append(nodes, nodes[len(nodes)-1])
		}

		// Pairing nodes to build a parent from the pair
		for i := 0; i < len(nodes); i += 2 {
			n := &Node{
				Left:  nodes[i],
				Right: nodes[i+1],

				// Compute the hash of the new node, which will be the combination of its children's hashes.
				Hash: t.h.Hash(nodes[i].Hash, nodes[i+1].Hash),
			}

			parents = append(parents, n)
			nodes[i].Parent, nodes[i+1].Parent = n, n
		}
		// Once all possible pairs are processed, the parents become the children, and we start all over again.
		nodes = parents
	}

	return nodes[0]
}
