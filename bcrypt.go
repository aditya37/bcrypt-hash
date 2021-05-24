package bcrypthash

import "golang.org/x/crypto/bcrypt"

type Hasher interface {
	HashPassword(password []byte) []byte
	ComparePassword(hash, password []byte) bool
}

type bcryptHash struct {
	cost int
}

// NewInstance BcryptHash
func NewBcryptHash(cost int) Hasher {
	return &bcryptHash{
		cost: cost,
	}
}

// Hash Password
func (bc *bcryptHash) HashPassword(password []byte) []byte {
	hash, err := bcrypt.GenerateFromPassword(password, bc.cost)
	if err == nil {
		return hash
	}
	return nil
}

// Compare password
func (bc *bcryptHash) ComparePassword(hash, password []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, password)
	return err == nil
}
