package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plain := make([]byte, 1<<16)
	if _, err := rand.Read(plain); err != nil {
		t.Fatal(err)
	}

	ct, key, nonce, err := Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len = %d, want 32", len(key))
	}
	if len(nonce) != 12 {
		t.Fatalf("nonce len = %d, want 12", len(nonce))
	}
	if bytes.Equal(ct, plain) {
		t.Fatal("ciphertext equals plaintext")
	}

	got, err := Decrypt(ct, key, nonce)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round-trip mismatch")
	}

	// Tampered ciphertext must fail (GCM auth).
	bad := bytes.Clone(ct)
	bad[0] ^= 0xff
	if _, err := Decrypt(bad, key, nonce); err == nil {
		t.Fatal("expected auth failure on tampered ciphertext")
	}
}

func TestLoadOrCreateIdentityPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "id.key")

	k1, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	k2, err := LoadOrCreateIdentity(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !k1.Equal(k2) {
		t.Fatal("reloaded key differs from created key")
	}
	if _, ok := any(k1).(ed25519.PrivateKey); !ok {
		t.Fatalf("not an ed25519 key: %T", k1)
	}
}

func TestFindURL(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want string
	}{
		{"public_url key", map[string]any{"Size": 1.0, "public_url": "https://xfl.jp/abcDEF"}, "https://xfl.jp/abcDEF"},
		{"nested Url", map[string]any{"data": map[string]any{"Url": "https://xfl.jp/zz"}}, "https://xfl.jp/zz"},
		{"bare string fallback", map[string]any{"x": "http://example.com/f"}, "http://example.com/f"},
		{"none", map[string]any{"x": "nope"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := findURL(c.in); got != c.want {
				t.Fatalf("findURL = %q, want %q", got, c.want)
			}
		})
	}
}
