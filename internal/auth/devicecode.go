package auth

import (
	"crypto/rand"
	"math/big"
	"sync"
	"time"
)

const (
	deviceCodeTTL = 5 * time.Minute
)

// DeviceCodeEntry holds the state of a single device code login session.
type DeviceCodeEntry struct {
	Token     string
	Username  string
	Completed bool
	expiresAt time.Time
}

// DeviceCodeStore is an in-memory store for CLI device code login sessions.
// It is safe for concurrent use.
type DeviceCodeStore struct {
	mu      sync.Mutex
	entries map[string]*DeviceCodeEntry
}

// NewDeviceCodeStore creates a new device code store.
func NewDeviceCodeStore() *DeviceCodeStore {
	return &DeviceCodeStore{
		entries: make(map[string]*DeviceCodeEntry),
	}
}

// Generate creates a new device code (e.g., "ABCD-1234") and stores it.
// Expired entries are cleaned up on each call.
func (s *DeviceCodeStore) Generate() (string, error) {
	code, err := generateDeviceCode()
	if err != nil {
		return "", err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Clean up expired entries
	now := time.Now()
	for k, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, k)
		}
	}

	s.entries[code] = &DeviceCodeEntry{
		expiresAt: now.Add(deviceCodeTTL),
	}
	return code, nil
}

// Complete marks a device code as completed with the auth result.
func (s *DeviceCodeStore) Complete(code, token, username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[code]
	if !ok || time.Now().After(entry.expiresAt) {
		return false
	}
	entry.Token = token
	entry.Username = username
	entry.Completed = true
	return true
}

// Poll checks the status of a device code.
func (s *DeviceCodeStore) Poll(code string) (token, username string, found, completed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[code]
	if !ok || time.Now().After(entry.expiresAt) {
		return "", "", false, false
	}
	return entry.Token, entry.Username, true, entry.Completed
}

// TTLSeconds returns the TTL for device codes in seconds.
func (s *DeviceCodeStore) TTLSeconds() int {
	return int(deviceCodeTTL.Seconds())
}

// generateDeviceCode creates a code like "ABCD-1234" (4 uppercase letters + 4 digits).
func generateDeviceCode() (string, error) {
	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ" // no I, O (avoid confusion with 1, 0)
	const digits = "0123456789"

	code := make([]byte, 9) // 4 letters + dash + 4 digits
	for i := 0; i < 4; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		code[i] = letters[n.Int64()]
	}
	code[4] = '-'
	for i := 5; i < 9; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		code[i] = digits[n.Int64()]
	}
	return string(code), nil
}
