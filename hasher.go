package mktree

import (
	"crypto/sha256"
	"hash"
	"io"
)

var DefaultShaHasher = NewHasher(sha256.New)

type HashFn func() hash.Hash

type Hasher struct {
	Imp HashFn
}

func NewHasher(imp HashFn) Hasher {
	return Hasher{imp}
}

func (hr *Hasher) Hash(data ...[]byte) []byte {
	h := hr.Imp()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

func (hr *Hasher) Hashable(data Hashable) ([]byte, error) {
	h := hr.Imp()
	if _, err := io.Copy(h, data); err != nil {
		return nil, err
	}

	return h.Sum(nil), nil
}
