package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/cybergodev/jwt/internal"
)

// Config is the unified configuration for JWT Processor.
// Use DefaultConfig() to get a configuration with sensible defaults.
type Config struct {
	// Signing configuration (choose one)
	SecretKey       string        // For HMAC algorithms (minimum 32 bytes)
	SigningKey      any           // For asymmetric algorithms (*rsa.PrivateKey or *ecdsa.PrivateKey)
	VerificationKey any           // Optional: public key for verification only (*rsa.PublicKey or *ecdsa.PublicKey)
	SigningMethod   SigningMethod // HS256, HS384, HS512, RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512

	// Token configuration
	// AccessTokenTTL is the lifetime of access tokens issued by Create.
	AccessTokenTTL time.Duration `yaml:"access_token_ttl" json:"access_token_ttl"`
	// RefreshTokenTTL is the lifetime of refresh tokens issued by CreateRefresh.
	// Must be greater than AccessTokenTTL.
	RefreshTokenTTL time.Duration `yaml:"refresh_token_ttl" json:"refresh_token_ttl"`
	// Issuer is written to the token's iss claim and checked during validation.
	Issuer string `yaml:"issuer" json:"issuer"`
	// ExpectedAudience, when non-empty, rejects tokens whose aud claim does not
	// contain this value during validation.
	ExpectedAudience string `yaml:"expected_audience" json:"expected_audience"`
	// RequireExpiration, when true, rejects tokens that lack an exp claim during
	// validation (Validate/ValidateInto/Refresh/RefreshInto) with ErrExpirationRequired.
	// Tokens issued by this processor always carry exp (derived from the TTL), so
	// this primarily governs tokens from other issuers or tokens missing exp —
	// without it, such a token never expires (RFC 7519 makes exp optional).
	// Default: false (historical behavior).
	RequireExpiration bool `yaml:"require_expiration" json:"require_expiration"`
	// ClockSkew is the leeway applied to exp and nbf during validation, to
	// tolerate clock drift between the token issuer and this validator. A token
	// is accepted up to ClockSkew after its exp, and from ClockSkew before its
	// nbf. Zero (the default) applies no leeway and reproduces the historical
	// strict timing checks; negative values are rejected by Validate.
	ClockSkew time.Duration `yaml:"clock_skew" json:"clock_skew"`

	// Blacklist configuration (embedded)
	Blacklist BlacklistConfig `yaml:"blacklist" json:"blacklist"`

	// Rate limiting
	// EnableRateLimit enables per-subject rate limiting on token creation.
	// When false (the default), the RateLimit* fields below are ignored.
	EnableRateLimit bool `yaml:"enable_rate_limit" json:"enable_rate_limit"`
	// RateLimitRate is the maximum number of tokens allowed per subject per window.
	RateLimitRate int `yaml:"rate_limit_rate" json:"rate_limit_rate"`
	// RateLimitWindow is the duration over which RateLimitRate is measured.
	RateLimitWindow time.Duration `yaml:"rate_limit_window" json:"rate_limit_window"`
	// RateLimiter optionally supplies a custom rate limiter. When nil and
	// EnableRateLimit is true, a built-in limiter is built from the fields above.
	RateLimiter RateLimitProvider `yaml:"-" json:"-"`

	// Clock provider for time operations (optional, defaults to SystemClock)
	Clock ClockProvider `yaml:"-" json:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
// The caller must set SecretKey (for HMAC) or SigningKey (for asymmetric) before use.
func DefaultConfig() Config {
	return Config{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "jwt-service",
		SigningMethod:   SigningMethodHS256,
		Blacklist:       DefaultBlacklistConfig(),
		RateLimitRate:   100,
		RateLimitWindow: time.Minute,
	}
}

// normalizeConfig fills in default values for zero fields.
// This allows users to provide minimal configuration while still getting sensible defaults.
func normalizeConfig(c Config) Config {
	defaults := DefaultConfig()

	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = defaults.AccessTokenTTL
	}
	if c.RefreshTokenTTL == 0 {
		c.RefreshTokenTTL = defaults.RefreshTokenTTL
	}
	if c.Issuer == "" {
		c.Issuer = defaults.Issuer
	}
	if c.SigningMethod == "" {
		c.SigningMethod = defaults.SigningMethod
	}
	if c.RateLimitRate == 0 && c.EnableRateLimit {
		c.RateLimitRate = defaults.RateLimitRate
	}
	if c.RateLimitWindow == 0 && c.EnableRateLimit {
		c.RateLimitWindow = defaults.RateLimitWindow
	}
	// Blacklist: apply per-field defaults when using built-in store
	if c.Blacklist.Store == nil {
		if c.Blacklist.MaxSize == 0 {
			c.Blacklist.MaxSize = defaults.Blacklist.MaxSize
		}
		if c.Blacklist.CleanupInterval == 0 {
			c.Blacklist.CleanupInterval = defaults.Blacklist.CleanupInterval
		}
		// For the built-in store, auto-cleanup is always enabled to prevent
		// unbounded memory growth. EnableAutoCleanup only takes effect with
		// a custom BlacklistStore.
		c.Blacklist.EnableAutoCleanup = true
	}

	return c
}

// Validate validates the configuration.
// Returns an error if the configuration is invalid.
//
// Returns errors:
//   - [ErrInvalidConfig]: nil config, invalid TTL values, or invalid blacklist config
//   - [ErrInvalidSecretKey]: missing key, key too short, weak key, wrong key type, or ECDSA curve mismatch
//   - [ErrInvalidSigningMethod]: unrecognized signing method
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	// Validate signing key based on method type
	if err := c.validateSigningKey(); err != nil {
		return err
	}

	if c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 {
		return fmt.Errorf("%w: TTL must be positive", ErrInvalidConfig)
	}

	if c.AccessTokenTTL >= c.RefreshTokenTTL {
		return fmt.Errorf("%w: access token TTL must be less than refresh token TTL", ErrInvalidConfig)
	}

	if c.ClockSkew < 0 {
		return fmt.Errorf("%w: clock skew must not be negative", ErrInvalidConfig)
	}

	if !c.SigningMethod.isValid() {
		return ErrInvalidSigningMethod
	}

	// Validate blacklist configuration
	if err := c.Blacklist.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}

	return nil
}

// validateSigningKey validates the signing key based on the signing method.
func (c *Config) validateSigningKey() error {
	switch {
	case c.SigningMethod.isHMAC():
		// HMAC requires SecretKey
		keyLen := len(c.SecretKey)
		if keyLen < 32 {
			return fmt.Errorf("%w: minimum 32 bytes required, got %d", ErrInvalidSecretKey, keyLen)
		}
		if internal.IsWeakKey([]byte(c.SecretKey)) {
			return fmt.Errorf("%w: key must have sufficient entropy and complexity", ErrInvalidSecretKey)
		}
	case c.SigningMethod.isAsymmetric():
		// Asymmetric methods use shared validation
		if err := validateAsymmetricSigningKey(c.SigningMethod, c.SigningKey); err != nil {
			return err
		}
		if err := validateVerificationKey(c.SigningMethod, c.VerificationKey); err != nil {
			return err
		}
	}
	return nil
}

// validateAsymmetricSigningKey validates asymmetric signing keys (RSA/ECDSA).
// This is shared between Config and AsymmetricConfig validation.
func validateAsymmetricSigningKey(method SigningMethod, key any) error {
	if key == nil {
		return fmt.Errorf("%w: SigningKey is required for %s method", ErrInvalidSecretKey, method)
	}
	switch method {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512:
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: RSA method requires *rsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA key cannot be nil", ErrInvalidSecretKey)
		}
		if rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA key must be at least 2048 bits, got %d", ErrInvalidSecretKey, rsaKey.N.BitLen())
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return fmt.Errorf("%w: ECDSA method requires *ecdsa.PrivateKey, got %T", ErrInvalidSecretKey, key)
		}
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA key cannot be nil", ErrInvalidSecretKey)
		}
		if err := validateECDSACurve(method, ecdsaKey.Curve); err != nil {
			return err
		}
	}
	return nil
}

// validateECDSACurve checks that the key's curve matches the expected curve for the signing method.
func validateECDSACurve(method SigningMethod, curve elliptic.Curve) error {
	var expected elliptic.Curve
	switch method {
	case SigningMethodES256:
		expected = elliptic.P256()
	case SigningMethodES384:
		expected = elliptic.P384()
	case SigningMethodES512:
		expected = elliptic.P521()
	default:
		return nil
	}
	if curve != expected {
		return fmt.Errorf("%w: %s requires %s curve, got %s",
			ErrInvalidSecretKey, method, expected.Params().Name, curve.Params().Name)
	}
	return nil
}

// validateVerificationKey validates the optional verification key for asymmetric methods.
// When nil, the SigningKey is used for both signing and verification.
func validateVerificationKey(method SigningMethod, key any) error {
	if key == nil {
		return nil
	}
	switch method {
	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodPS256, SigningMethodPS384, SigningMethodPS512:
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *rsa.PublicKey for RSA, got %T", ErrInvalidSecretKey, key)
		}
		if rsaKey == nil {
			return fmt.Errorf("%w: RSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
		if rsaKey.N.BitLen() < 2048 {
			return fmt.Errorf("%w: RSA VerificationKey must be at least 2048 bits, got %d", ErrInvalidSecretKey, rsaKey.N.BitLen())
		}
	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		ecdsaKey, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: VerificationKey must be *ecdsa.PublicKey for ECDSA, got %T", ErrInvalidSecretKey, key)
		}
		if ecdsaKey == nil {
			return fmt.Errorf("%w: ECDSA VerificationKey cannot be nil", ErrInvalidSecretKey)
		}
	}
	return nil
}
