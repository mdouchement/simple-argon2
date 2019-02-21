// Package argon2 provides a convenience wrapper around Go's existing argon2 package
// that makes it easier to securely derive strong keys from weak
// inputs (i.e. user passwords).
// The package provides password generation and comparison for argon2 derived keys.
package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// MinIterations is the minimum iterations (or passes) over the memory.
	MinIterations = 1
	// MinParallelism is the minimum of threads (or lanes) used by the algorithm.
	MinParallelism = 1
	// MinSaltLength is the minimum length of the random salt.
	MinSaltLength = 16
	// MinKeyLength is the minimum length of the generated key (or password hash).
	MinKeyLength = 16
)

// Params describes the input parameters to the argon2
// key derivation function.
// https://tools.ietf.org/html/draft-irtf-cfrg-argon2-04
// https://github.com/P-H-C/phc-winner-argon2
type Params struct {
	// Memory is the amount of memory used by the algorithm (in kibibytes).
	Memory uint32
	// Iterations is the number of iterations (or passes) over the memory.
	Iterations uint32
	// Parallelism is the number of threads (or lanes) used by the algorithm.
	Parallelism uint8
	// SaltLength is the length of the random salt
	SaltLength uint32
	// KeyLength is the length of the generated key (or password hash).
	KeyLength uint32
}

var (
	// Default provides sensible default inputs into the argon2 function.
	Default = Params{
		Memory:      64 * 1024,
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	// ErrInvalidHash is returned when failing to parse a provided argon2
	// hash and/or parameters.
	ErrInvalidHash = errors.New("argon2: the encoded hash is not in the correct format")
	// ErrIncompatibleVersion is returned when the provided hashed password is incompatible with this lib.
	ErrIncompatibleVersion = errors.New("argon2: incompatible version")
	// ErrMismatchedHashAndPassword is returned when a password (hashed) and
	// given hash do not match.
	ErrMismatchedHashAndPassword = errors.New("argon2: the hashed password does not match the hash of the given password")
)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// err == nil only if len(b) == n
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateFromPasswordString returns the derived key of the password using the
// parameters provided. The parameters are prepended to the derived key and
// separated by the "$" character (0x24).
// If the parameters provided are less than the minimum acceptable values,
// the values are setted to the default.
func GenerateFromPasswordString(password string, p Params) (string, error) {
	hp, err := GenerateFromPassword([]byte(password), p)
	return string(hp), err
}

// GenerateFromPassword returns the derived key of the password using the
// parameters provided. The parameters are prepended to the derived key and
// separated by the "$" character (0x24).
// If the parameters provided are less than the minimum acceptable values,
// the values are setted to the default.
func GenerateFromPassword(password []byte, p Params) ([]byte, error) {
	if p.Iterations < MinIterations {
		p.Iterations = Default.Iterations
	}
	if p.Parallelism < MinParallelism {
		p.Parallelism = Default.Parallelism
	}
	if p.SaltLength < MinSaltLength {
		p.SaltLength = Default.SaltLength
	}
	if p.KeyLength < MinKeyLength {
		p.KeyLength = Default.KeyLength
	}

	hp, err := newFromPassword(password, p)
	if err != nil {
		return nil, err
	}

	return hp.Hash(), nil
}

// CompareHashAndPasswordString compares a derived key with the possible cleartext
// equivalent. The parameters used in the provided derived key are used.
// It returns nil on success, and an error if the derived keys do not match.
func CompareHashAndPasswordString(hashedPassword, password string) error {
	return CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

// CompareHashAndPassword compares a derived key with the possible cleartext
// equivalent. The parameters used in the provided derived key are used.
// It returns nil on success, and an error if the derived keys do not match.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	// Decode existing hash, retrieve params and salt.
	h, err := newFromHash(hashedPassword)
	if err != nil {
		return err
	}

	// Hash given plain-text password
	hash := argon2.IDKey(password, h.salt, h.p.Iterations, h.p.Memory, h.p.Parallelism, h.p.KeyLength)

	// Constant time comparison
	if subtle.ConstantTimeCompare(h.hash, hash) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

///////////////////////
//                   //
// hashed            //
//                   //
///////////////////////

type hashed struct {
	p    Params
	hash []byte
	salt []byte
}

func newFromPassword(password []byte, p Params) (*hashed, error) {
	salt, err := GenerateRandomBytes(p.SaltLength)
	if err != nil {
		return nil, err
	}

	return &hashed{
		p:    p,
		salt: salt,
		hash: argon2.IDKey(password, salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength),
	}, nil
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	parts := strings.Split(string(hashedSecret), "$")
	if len(parts) != 6 {
		return nil, ErrInvalidHash
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, err
	}
	if version != argon2.Version {
		return nil, ErrIncompatibleVersion
	}

	h := &hashed{}
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.p.Memory, &h.p.Iterations, &h.p.Parallelism)
	if err != nil {
		return nil, err
	}

	//
	// Parse salt
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, err
	}
	h.salt = salt
	h.p.SaltLength = uint32(len(salt))

	//
	// Parse key
	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, err
	}
	h.hash = hash
	h.p.KeyLength = uint32(len(hash))

	return h, nil
}

func (h *hashed) Hash() []byte {
	// Base64 encode the salt and hashed password.
	b64Salt := base64.RawStdEncoding.EncodeToString(h.salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(h.hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.Memory, h.p.Iterations, h.p.Parallelism, b64Salt, b64Hash)
	return []byte(encoded)
}
