package argon2_test

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	argon2 "github.com/mdouchement/simple-argon2"
	"github.com/stretchr/testify/assert"
	goArgon2 "golang.org/x/crypto/argon2"
)

func TestGenerateRandomBytes(t *testing.T) {
	for _, v := range []uint32{1, 8, 16, 32, 128, 512, 8192} {
		salt, err := argon2.GenerateRandomBytes(v)
		assert.Nil(t, err)
		assert.Equal(t, int(v), len(salt))
	}
}

func TestArgon2(t *testing.T) {
	password := randPassword()
	fmt.Printf("Password: '%s'\n", password)

	var data = []struct {
		password    string
		params      argon2.Params
		memory      uint32
		iterations  uint32
		parallelism uint8
		saltLength  uint32
		keyLength   uint32
	}{
		{
			password:    password,
			params:      argon2.Default,
			memory:      argon2.Default.Memory,
			iterations:  argon2.Default.Iterations,
			parallelism: argon2.Default.Parallelism,
			saltLength:  argon2.Default.SaltLength,
			keyLength:   argon2.Default.KeyLength,
		},
		{
			password: password,
			params: argon2.Params{
				Memory:      0,
				Iterations:  0,
				Parallelism: 0,
				SaltLength:  0,
				KeyLength:   0,
			},
			memory:      0,
			iterations:  argon2.Default.Iterations,
			parallelism: argon2.Default.Parallelism,
			saltLength:  argon2.Default.SaltLength,
			keyLength:   argon2.Default.KeyLength,
		},
		{
			password: password,
			params: argon2.Params{
				Memory:      argon2.Default.Memory,
				Iterations:  argon2.MinIterations - 1,
				Parallelism: argon2.MinParallelism - 1,
				SaltLength:  argon2.MinSaltLength - 1,
				KeyLength:   argon2.MinKeyLength - 1,
			},
			memory:      argon2.Default.Memory,
			iterations:  argon2.Default.Iterations,
			parallelism: argon2.Default.Parallelism,
			saltLength:  argon2.Default.SaltLength,
			keyLength:   argon2.Default.KeyLength,
		},
		{
			password: password,
			params: argon2.Params{
				Memory:      argon2.Default.Memory,
				Iterations:  argon2.MinIterations,
				Parallelism: argon2.MinParallelism,
				SaltLength:  argon2.MinSaltLength,
				KeyLength:   argon2.MinKeyLength,
			},
			memory:      argon2.Default.Memory,
			iterations:  argon2.MinIterations,
			parallelism: argon2.MinParallelism,
			saltLength:  argon2.MinSaltLength,
			keyLength:   argon2.MinKeyLength,
		},
	}

	for _, d := range data {
		hashed, err := argon2.GenerateFromPasswordString(d.password, d.params)
		assert.Nil(t, err)

		parts := strings.Split(hashed, "$")
		assert.Equal(t, 6, len(parts))

		//
		// Version
		var version int
		_, err = fmt.Sscanf(parts[2], "v=%d", &version)
		assert.Nil(t, err)
		assert.Equal(t, goArgon2.Version, version)

		//
		// Params
		var p argon2.Params
		_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
		assert.Nil(t, err)
		assert.Equal(t, d.memory, p.Memory)
		assert.Equal(t, d.iterations, p.Iterations)
		assert.Equal(t, d.parallelism, p.Parallelism)

		//
		// Salt length
		salt, err := base64.RawStdEncoding.DecodeString(parts[4])
		assert.Nil(t, err)
		assert.Equal(t, int(d.saltLength), len(salt))

		//
		// Key length
		hash, err := base64.RawStdEncoding.DecodeString(parts[5])
		assert.Nil(t, err)
		assert.Equal(t, int(d.keyLength), len(hash))

		//
		// Compare password
		err = argon2.CompareHashAndPasswordString(hashed, d.password)
		assert.Nil(t, err)
	}
}

func randPassword() string {
	pool := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_+=()?<>,.!@#$%^&*~[]{}/|\\éèä®ŷÏÄÃÒÉ⁄™‹›")
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))

	b := make([]rune, rnd.Intn(42))
	for i := range b {
		b[i] = pool[rnd.Intn(len(pool))]
	}
	return string(b)

}
