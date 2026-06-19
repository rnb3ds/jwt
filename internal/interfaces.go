package internal

import (
	"time"
)

// Store is the internal blacklist storage contract: record a token id with its
// expiry, test membership, proactively evict expired entries (Cleanup), and
// release resources (Close). Implementations must be safe for concurrent use.
type Store interface {
	Add(tokenID string, expiresAt time.Time) error
	Contains(tokenID string) (bool, error)
	Cleanup() (int, error)
	Close() error
}
