package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argon2idPrefix = "$argon2id$"
	argon2idFormat = "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"
)

// hashPasswordArgon2id hashes the password using Argon2id algorithm.
func hashPasswordArgon2id(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, 3, 65536, 4, 32)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	return fmt.Sprintf(argon2idFormat, argon2.Version, 65536, 3, 4, b64Salt, b64Hash), nil
}

// verifyPasswordArgon2id verifies the password against a stored Argon2id hash.
func verifyPasswordArgon2id(hashedPassword, password string) (bool, error) {
	if !strings.HasPrefix(hashedPassword, argon2idPrefix) {
		return false, errors.New("invalid argon2id hash format")
	}

	parts := strings.Split(hashedPassword, "$")
	if len(parts) != 6 {
		return false, errors.New("invalid argon2id hash format")
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != argon2.Version {
		return false, fmt.Errorf("incompatible argon2 version: %d", version)
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, err
	}

	maxParallel := runtime.GOMAXPROCS(0)
	if maxParallel < 1 {
		maxParallel = 1
	}
	if maxParallel > 32 {
		maxParallel = 32
	}

	if memory < 1024 || memory > 1024*1024 {
		return false, fmt.Errorf("argon2id memory cost out of bounds: %d", memory)
	}
	if iterations < 1 || iterations > 100 {
		return false, fmt.Errorf("argon2id iterations cost out of bounds: %d", iterations)
	}
	if parallelism < 1 || int(parallelism) > maxParallel {
		return false, fmt.Errorf("argon2id parallelism cost out of bounds: %d", parallelism)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, err
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, err
	}

	hashLen := len(hash)
	if hashLen <= 0 || hashLen > 64 {
		return false, fmt.Errorf("invalid argon2id key length: %d", hashLen)
	}

	expectedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(hashLen)) //#nosec G115 -- bounds checked above

	if subtle.ConstantTimeCompare(hash, expectedHash) == 1 {
		return true, nil
	}

	return false, nil
}
