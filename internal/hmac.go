package internal

import (
	"crypto"
	"crypto/hmac"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"sync"
)

type hmacSigningMethod struct {
	Name     string
	HashFunc crypto.Hash
	pool     sync.Pool
}

// hashOutputSize is the largest hash digest produced by any supported algorithm
// (SHA-512 = 64 bytes, used by HS512/RS512/PS512/ES512). It sizes the reusable
// Sum output buffer stored on each pooled hasher.
const hashOutputSize = 64

// hasherBuf wraps a plain hash.Hash (used by the RSA/ECDSA paths) with a
// reusable Sum output buffer. Co-locating sum with the pooled hasher avoids the
// per-call [64]byte stack escape that hasher.Sum would otherwise incur — Sum is
// an interface method, so the compiler conservatively escapes its append
// argument; a heap-resident buffer (the pooled entry) is not re-allocated.
type hasherBuf struct {
	hash.Hash
	sum [hashOutputSize]byte
}

// hasherEntry wraps a pooled HMAC hasher with its associated key (for identity
// verification on retrieval) and a reusable Sum output buffer.
//
// sum is heap-resident because the entry is pooled. Passing sum[:0] to
// hasher.Sum therefore avoids the per-call [64]byte stack escape that a local
// `var buf [64]byte` incurs — Sum is an interface method, so the compiler
// conservatively escapes its append argument. Co-locating the scratch buffer
// with the pooled hasher removes one allocation from every sign and verify.
type hasherEntry struct {
	key    []byte
	hasher hash.Hash
	sum    [hashOutputSize]byte
}

// getHasher returns a pooled hasherEntry keyed by key. On a key match the entry
// is reused as-is; on a mismatch or pool miss the entry is (re)built in place,
// so the returned entry always carries hasher/key consistent with key. Callers
// must return the entry via putHasher.
func (h *hmacSigningMethod) getHasher(key []byte) *hasherEntry {
	if v := h.pool.Get(); v != nil {
		entry := v.(*hasherEntry)
		if len(entry.key) == len(key) && subtle.ConstantTimeCompare(entry.key, key) == 1 {
			return entry
		}
		// Key changed: reuse the entry struct for the new hasher + key copy.
		ZeroBytes(entry.key)
		keyCopy := make([]byte, len(key))
		copy(keyCopy, key)
		entry.key = keyCopy
		entry.hasher = hmac.New(h.HashFunc.New, key)
		return entry
	}
	// Pool miss (cold): allocate the entry once; it is reused on every subsequent call.
	entry := &hasherEntry{}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	entry.key = keyCopy
	entry.hasher = hmac.New(h.HashFunc.New, key)
	return entry
}

// putHasher returns a hasher entry to the pool. getHasher keeps the entry's
// hasher/key fields in sync, so there is nothing to repair here.
func (h *hmacSigningMethod) putHasher(entry *hasherEntry) {
	h.pool.Put(entry)
}

func (h *hmacSigningMethod) Verify(signingString string, signature string, key any) error {
	keyBytes, ok := key.([]byte)
	if !ok {
		return errors.New("invalid key type: HMAC requires []byte key")
	}
	return h.verify(signingString, signature, keyBytes)
}

// VerifyHMAC is a type-specialized variant of Verify that accepts []byte directly,
// avoiding the interface boxing overhead.
func (h *hmacSigningMethod) VerifyHMAC(signingString string, signature string, key []byte) error {
	return h.verify(signingString, signature, key)
}

// verify holds the shared verification body. Callers pass key as []byte so the
// HMAC-specialized path (VerifyHMAC) avoids the any-boxing that Verify incurs.
func (h *hmacSigningMethod) verify(signingString string, signature string, key []byte) error {
	if !h.HashFunc.Available() {
		return fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	// Stack-allocated decode buffer for signature (max HMAC sig: 64 bytes for SHA512)
	var sigBuf [64]byte
	decodedLen := base64.RawURLEncoding.DecodedLen(len(signature))
	if decodedLen > len(sigBuf) {
		return errors.New("signature verification failed")
	}
	sigBytes := sigBuf[:decodedLen]
	n, err := base64.RawURLEncoding.Decode(sigBytes, stringToBytes(signature))
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}
	sigBytes = sigBytes[:n]

	if len(sigBytes) != h.HashFunc.Size() {
		return errors.New("signature verification failed")
	}

	e := h.getHasher(key)
	defer h.putHasher(e)
	e.hasher.Reset()
	e.hasher.Write(stringToBytes(signingString))

	// e.sum is heap-resident (pooled entry), so Sum does not escape a stack buffer.
	if !hmac.Equal(sigBytes, e.hasher.Sum(e.sum[:0])) {
		return errors.New("signature verification failed")
	}

	return nil
}

func (h *hmacSigningMethod) Sign(signingString string, key any) (string, error) {
	var buf [86]byte // max HS512: 64 bytes → 86 base64 chars
	n, err := h.SignTo(buf[:], signingString, key)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (h *hmacSigningMethod) Alg() string {
	return h.Name
}

func (h *hmacSigningMethod) Hash() crypto.Hash {
	return h.HashFunc
}

func (h *hmacSigningMethod) SignTo(dst []byte, signingString string, key any) (int, error) {
	keyBytes, ok := key.([]byte)
	if !ok {
		return 0, errors.New("invalid key type: HMAC requires []byte key")
	}
	return h.signTo(dst, signingString, keyBytes)
}

// SignToHMAC is a type-specialized variant of SignTo that accepts []byte directly,
// avoiding the interface boxing overhead that causes key escape.
func (h *hmacSigningMethod) SignToHMAC(dst []byte, signingString string, key []byte) (int, error) {
	return h.signTo(dst, signingString, key)
}

// signTo holds the shared signing body (see verify for the []byte-key rationale).
func (h *hmacSigningMethod) signTo(dst []byte, signingString string, key []byte) (int, error) {
	if !h.HashFunc.Available() {
		return 0, fmt.Errorf("hash function %v not available", h.HashFunc)
	}

	e := h.getHasher(key)
	defer h.putHasher(e)
	e.hasher.Reset()
	e.hasher.Write(stringToBytes(signingString))

	hashed := e.hasher.Sum(e.sum[:0])

	encodedLen := base64.RawURLEncoding.EncodedLen(len(hashed))
	if len(dst) < encodedLen {
		return 0, fmt.Errorf("signature buffer too small: need %d, have %d", encodedLen, len(dst))
	}
	base64.RawURLEncoding.Encode(dst[:encodedLen], hashed)
	return encodedLen, nil
}

var (
	hmacHS256 = &hmacSigningMethod{"HS256", crypto.SHA256, sync.Pool{}}
	hmacHS384 = &hmacSigningMethod{"HS384", crypto.SHA384, sync.Pool{}}
	hmacHS512 = &hmacSigningMethod{"HS512", crypto.SHA512, sync.Pool{}}
)

// ClearHMACCaches drains all HMAC hasher pools, allowing GC to reclaim
// hasher objects that may retain secret key material in their internal state.
func ClearHMACCaches() {
	hmacHS256.drainPool()
	hmacHS384.drainPool()
	hmacHS512.drainPool()
}

// drainPool removes all entries from the pool, zeroing key material and resetting
// hashers before allowing GC to reclaim them.
func (h *hmacSigningMethod) drainPool() {
	for {
		v := h.pool.Get()
		if v == nil {
			return
		}
		entry := v.(*hasherEntry)
		ZeroBytes(entry.key)
		entry.hasher.Reset()
	}
}
