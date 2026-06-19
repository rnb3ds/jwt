//go:build example

package main

import (
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/cybergodev/jwt"
)

// Extensibility features demonstration.
// Covers documented features not shown in the other examples:
//   - Audience validation (ExpectedAudience)
//   - Clock injection (FixedClock) for deterministic, sleep-free testing
//   - Custom BlacklistStore backend (e.g. Redis)
//
// Run with:  go run -tags example ./examples/extensibility
func main() {
	fmt.Println("JWT Library - Extensibility")
	fmt.Println("===========================")

	const secretKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// Example 1: Audience validation
	audienceExample(secretKey)

	fmt.Println()

	// Example 2: Clock injection
	clockExample(secretKey)

	fmt.Println()

	// Example 3: Custom blacklist store
	customStoreExample(secretKey)

	fmt.Println("\nExtensibility example complete!")
}

// audienceExample shows issuer/audience (iss/aud) enforcement.
// Tokens whose aud claim does not contain ExpectedAudience are rejected.
func audienceExample(secretKey string) {
	fmt.Println("Example 1: Audience Validation")
	fmt.Println("------------------------------")

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	cfg.ExpectedAudience = "billing-api" // reject tokens without this audience
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer p.Close()

	// Audience is a registered claim; set it via the embedded RegisteredClaims.
	// (Promoted fields cannot be named directly in a composite literal.)
	matchingClaims := jwt.Claims{
		UserID: "user-billing",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.StringOrSlice{"billing-api"},
		},
	}
	token, err := p.Create(&matchingClaims)
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	_, valid, err := p.Validate(token)
	fmt.Printf("Token for billing-api: valid=%v\n", valid)

	// A token issued for a different audience is rejected by Validate.
	mismatchClaims := jwt.Claims{
		UserID: "user-admin",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.StringOrSlice{"admin-api"},
		},
	}
	mismatchToken, err := p.Create(&mismatchClaims)
	if err != nil {
		log.Fatalf("Failed to create mismatch token: %v", err)
	}
	_, valid, err = p.Validate(mismatchToken)
	fmt.Printf("Token for admin-api:   valid=%v (audience mismatch=%v)\n",
		valid, errors.Is(err, jwt.ErrTokenInvalidAudience))
}

// clockExample shows FixedClock-based time injection. By pointing the issuer
// and validator at different fixed instants with the same key, token expiry
// can be exercised deterministically without time.Sleep.
func clockExample(secretKey string) {
	fmt.Println("Example 2: Clock Injection")
	fmt.Println("--------------------------")

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	// Issuer's clock is "now"; token expires after 1 minute.
	issuerCfg := jwt.DefaultConfig()
	issuerCfg.SecretKey = secretKey
	issuerCfg.Clock = jwt.FixedClock{T: now}
	issuerCfg.AccessTokenTTL = time.Minute
	issuer, err := jwt.New(issuerCfg)
	if err != nil {
		log.Fatalf("Failed to create issuer: %v", err)
	}
	defer issuer.Close()

	token, err := issuer.Create(&jwt.Claims{UserID: "clock-user"})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	// Same key, but the validator's clock is 2 minutes later -> token expired.
	validatorCfg := jwt.DefaultConfig()
	validatorCfg.SecretKey = secretKey
	validatorCfg.Clock = jwt.FixedClock{T: now.Add(2 * time.Minute)}
	validatorCfg.AccessTokenTTL = time.Minute
	validator, err := jwt.New(validatorCfg)
	if err != nil {
		log.Fatalf("Failed to create validator: %v", err)
	}
	defer validator.Close()

	_, valid, err := validator.Validate(token)
	fmt.Printf("Validated with clock 2 min past issue: valid=%v (expired=%v)\n",
		valid, errors.Is(err, jwt.ErrTokenExpired))
}

// memoryBlacklistStore is a minimal BlacklistStore backed by a map.
// Implementations for production use Redis, a database, etc. — the interface
// is the same. It must be safe for concurrent use.
type memoryBlacklistStore struct {
	mu    sync.Mutex
	items map[string]time.Time // tokenID -> expiry
	now   func() time.Time
}

func newMemoryBlacklistStore() *memoryBlacklistStore {
	return &memoryBlacklistStore{
		items: make(map[string]time.Time),
		now:   time.Now,
	}
}

// Add records a token ID with its expiry time.
func (s *memoryBlacklistStore) Add(tokenID string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[tokenID] = expiresAt
	return nil
}

// Contains reports whether the token ID is present and not expired.
func (s *memoryBlacklistStore) Contains(tokenID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.items[tokenID]
	if !ok {
		return false, nil
	}
	if s.now().After(exp) {
		delete(s.items, tokenID) // lazy expiry
		return false, nil
	}
	return true, nil
}

// Close releases resources (none for this in-memory implementation).
func (s *memoryBlacklistStore) Close() error { return nil }

// customStoreExample wires a custom BlacklistStore into the processor.
// Revoke/IsRevoked/Validate then consult the custom backend transparently.
func customStoreExample(secretKey string) {
	fmt.Println("Example 3: Custom Blacklist Store")
	fmt.Println("---------------------------------")

	store := newMemoryBlacklistStore()

	cfg := jwt.DefaultConfig()
	cfg.SecretKey = secretKey
	// Providing Store makes the processor use it for all blacklist operations;
	// MaxSize/CleanupInterval/EnableAutoCleanup are ignored with a custom store.
	cfg.Blacklist = jwt.BlacklistConfig{Store: store}
	p, err := jwt.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create processor: %v", err)
	}
	defer p.Close()

	token, err := p.Create(&jwt.Claims{UserID: "store-user", Username: "store-user"})
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	revokedBefore, _ := p.IsRevoked(token)
	if err := p.Revoke(token); err != nil {
		log.Fatalf("Failed to revoke token: %v", err)
	}
	revokedAfter, _ := p.IsRevoked(token)
	_, validAfter, _ := p.Validate(token)
	fmt.Printf("Custom store revocation: before=%v, after=%v, validate=%v\n",
		revokedBefore, revokedAfter, !validAfter)
}
