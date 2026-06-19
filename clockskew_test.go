package jwt

import (
	"errors"
	"testing"
	"time"
)

// TestClockSkew covers the Config.ClockSkew leeway applied to exp and nbf.
// A zero ClockSkew preserves the historical strict timing checks (regression
// guard); a positive ClockSkew widens the acceptance window symmetrically.
func TestClockSkew(t *testing.T) {
	now := time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC)
	// Strong key that passes IsWeakKey (matches the examples).
	const strongKey = "Kx9#mP2$vL8@nQ5!wR7&tY3^uI6*oE4%aS1+dF0-gH9~jK2#bN5$cM8@xZ7&vB4!"

	// newProc builds a processor whose clock is fixed at `now` with an optional
	// config mutation. Validation uses the same fixed clock.
	newProc := func(t *testing.T, mod func(*Config)) *Processor {
		t.Helper()
		cfg := DefaultConfig()
		cfg.SecretKey = strongKey
		cfg.Clock = FixedClock{T: now}
		mod(&cfg)
		p, err := New(cfg)
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}

	// issue signs a token whose ExpiresAt = now+expOff and NotBefore = now+nbfOff.
	// Create does not run timing checks, so past/future timestamps are accepted
	// at issuance; timing is enforced on the Validate path.
	issue := func(t *testing.T, p *Processor, expOff, nbfOff time.Duration) string {
		t.Helper()
		c := &Claims{UserID: "skew-user", Username: "test"}
		c.ExpiresAt = NewNumericDate(now.Add(expOff))
		c.NotBefore = NewNumericDate(now.Add(nbfOff))
		tok, err := p.Create(c)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}
		return tok
	}

	const skew = 30 * time.Second
	cases := []struct {
		name      string
		clockSkew time.Duration
		expOff    time.Duration
		nbfOff    time.Duration
		wantErr   error // nil == token accepted
	}{
		{"exp just past, no skew -> expired", 0, -10 * time.Second, 0, ErrTokenExpired},
		{"exp just past, within skew -> valid", skew, -10 * time.Second, 0, nil},
		{"exp past beyond skew -> expired", skew, -40 * time.Second, 0, ErrTokenExpired},
		{"nbf just future, no skew -> not valid yet", 0, time.Hour, 10 * time.Second, ErrTokenNotValidYet},
		{"nbf just future, within skew -> valid", skew, time.Hour, 10 * time.Second, nil},
		{"nbf future beyond skew -> not valid yet", skew, time.Hour, 40 * time.Second, ErrTokenNotValidYet},
		{"zero skew, valid token still valid", 0, time.Hour, 0, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newProc(t, func(c *Config) { c.ClockSkew = tc.clockSkew })
			tok := issue(t, p, tc.expOff, tc.nbfOff)

			_, valid, err := p.Validate(tok)
			if tc.wantErr == nil {
				if err != nil || !valid {
					t.Fatalf("expected valid token, got valid=%v err=%v", valid, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("expected %v, got %v", tc.wantErr, err)
			}
			if valid {
				t.Error("expected valid=false when an error is returned")
			}
		})
	}

	t.Run("negative skew rejected at construction", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.SecretKey = strongKey
		cfg.ClockSkew = -1 * time.Second
		_, err := New(cfg)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("expected ErrInvalidConfig for negative skew, got %v", err)
		}
	})
}
