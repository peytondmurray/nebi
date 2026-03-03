package auth

import (
	"strings"
	"testing"
	"time"
)

func TestDeviceCodeStore_Generate(t *testing.T) {
	store := NewDeviceCodeStore()

	code, err := store.Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}

	// Code should be "XXXX-0000" format (4 letters, dash, 4 digits)
	if len(code) != 9 {
		t.Errorf("expected code length 9, got %d: %q", len(code), code)
	}
	if code[4] != '-' {
		t.Errorf("expected dash at position 4, got %q", code)
	}

	// Letters part should be uppercase, no I or O
	for _, ch := range code[:4] {
		if ch < 'A' || ch > 'Z' || ch == 'I' || ch == 'O' {
			t.Errorf("unexpected character in letter part: %c", ch)
		}
	}

	// Digits part should be 0-9
	for _, ch := range code[5:] {
		if ch < '0' || ch > '9' {
			t.Errorf("unexpected character in digit part: %c", ch)
		}
	}
}

func TestDeviceCodeStore_GenerateUnique(t *testing.T) {
	store := NewDeviceCodeStore()
	seen := make(map[string]bool)

	for i := 0; i < 50; i++ {
		code, err := store.Generate()
		if err != nil {
			t.Fatalf("Generate() error: %v", err)
		}
		if seen[code] {
			t.Errorf("duplicate code generated: %q", code)
		}
		seen[code] = true
	}
}

func TestDeviceCodeStore_PollPending(t *testing.T) {
	store := NewDeviceCodeStore()

	code, _ := store.Generate()
	token, username, found, completed := store.Poll(code)

	if !found {
		t.Fatal("expected code to be found")
	}
	if completed {
		t.Error("expected code to not be completed")
	}
	if token != "" || username != "" {
		t.Errorf("expected empty token/username, got %q/%q", token, username)
	}
}

func TestDeviceCodeStore_PollUnknown(t *testing.T) {
	store := NewDeviceCodeStore()

	_, _, found, _ := store.Poll("ZZZZ-9999")
	if found {
		t.Error("expected unknown code to not be found")
	}
}

func TestDeviceCodeStore_Complete(t *testing.T) {
	store := NewDeviceCodeStore()

	code, _ := store.Generate()
	ok := store.Complete(code, "jwt-token-123", "admin")
	if !ok {
		t.Fatal("Complete() returned false")
	}

	token, username, found, completed := store.Poll(code)
	if !found {
		t.Fatal("expected code to be found after complete")
	}
	if !completed {
		t.Error("expected code to be completed")
	}
	if token != "jwt-token-123" {
		t.Errorf("expected token %q, got %q", "jwt-token-123", token)
	}
	if username != "admin" {
		t.Errorf("expected username %q, got %q", "admin", username)
	}
}

func TestDeviceCodeStore_CompleteUnknown(t *testing.T) {
	store := NewDeviceCodeStore()

	ok := store.Complete("ZZZZ-9999", "token", "user")
	if ok {
		t.Error("expected Complete() to return false for unknown code")
	}
}

func TestDeviceCodeStore_Expiry(t *testing.T) {
	// Create a store and manually insert an expired entry
	store := NewDeviceCodeStore()

	store.mu.Lock()
	store.entries["EXPR-0000"] = &DeviceCodeEntry{
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	store.mu.Unlock()

	// Poll should not find expired entry
	_, _, found, _ := store.Poll("EXPR-0000")
	if found {
		t.Error("expected expired code to not be found")
	}

	// Complete should fail on expired entry
	ok := store.Complete("EXPR-0000", "token", "user")
	if ok {
		t.Error("expected Complete() to return false for expired code")
	}
}

func TestDeviceCodeStore_CleanupOnGenerate(t *testing.T) {
	store := NewDeviceCodeStore()

	// Insert an expired entry
	store.mu.Lock()
	store.entries["OLD-0000"] = &DeviceCodeEntry{
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	store.mu.Unlock()

	// Generate should clean up expired entries
	_, _ = store.Generate()

	store.mu.Lock()
	_, exists := store.entries["OLD-0000"]
	store.mu.Unlock()

	if exists {
		t.Error("expected expired entry to be cleaned up after Generate()")
	}
}

func TestDeviceCodeStore_TTLSeconds(t *testing.T) {
	store := NewDeviceCodeStore()
	ttl := store.TTLSeconds()
	if ttl != 300 {
		t.Errorf("expected TTL 300 seconds, got %d", ttl)
	}
}

func TestGenerateDeviceCode_Format(t *testing.T) {
	// Run multiple times to check consistency
	for i := 0; i < 20; i++ {
		code, err := generateDeviceCode()
		if err != nil {
			t.Fatalf("generateDeviceCode() error: %v", err)
		}

		parts := strings.Split(code, "-")
		if len(parts) != 2 {
			t.Errorf("expected 2 parts separated by dash, got %d: %q", len(parts), code)
			continue
		}
		if len(parts[0]) != 4 {
			t.Errorf("expected 4 letter prefix, got %d: %q", len(parts[0]), parts[0])
		}
		if len(parts[1]) != 4 {
			t.Errorf("expected 4 digit suffix, got %d: %q", len(parts[1]), parts[1])
		}
	}
}
