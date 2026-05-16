// Package proto holds the wire types and shared helpers used by both the
// gosigner daemon and the signreq client: the Spot request/response
// envelope, per-transfer AES-256-GCM file encryption, the static ed25519
// identity store, and Util/TempFile upload/download (tunneled through Spot).
package proto

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/KarpelesLab/rest"
)

// Endpoint is the default Spot handler name the daemon listens on and the
// client sends to (overridable on both sides).
const Endpoint = "sign"

// SignRequest is the JSON body sent by signreq to the daemon inside an
// end-to-end-encrypted Spot message. URL points at an AES-256-GCM
// encrypted blob on Util/TempFile; Key/Nonce decrypt it. ProgramName
// and ProgramURL populate the SpcSpOpusInfo signed attribute (the
// publisher's display name and "more info" link surfaced by Authenticode
// verifiers); both optional, both default to empty / omitted.
type SignRequest struct {
	Secret      string `json:"secret"`
	URL         string `json:"url"`
	Key         []byte `json:"key"`   // 32 bytes (base64 in JSON)
	Nonce       []byte `json:"nonce"` // 12 bytes (base64 in JSON)
	Filename    string `json:"filename"`
	ProgramName string `json:"program_name,omitempty"`
	ProgramURL  string `json:"program_url,omitempty"`
}

// SignResponse is the JSON body the daemon returns (also inside an
// end-to-end-encrypted Spot reply) pointing at the encrypted signed file.
type SignResponse struct {
	URL      string `json:"url"`
	Key      []byte `json:"key"`
	Nonce    []byte `json:"nonce"`
	Filename string `json:"filename"`
}

// Encrypt seals plain with a fresh random AES-256-GCM key and nonce.
// Returns the ciphertext, the 32-byte key and the 12-byte nonce.
func Encrypt(plain []byte) (ciphertext, key, nonce []byte, err error) {
	key = make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, nil, err
	}
	return gcm.Seal(nil, nonce, plain, nil), key, nonce, nil
}

// Decrypt opens a ciphertext produced by Encrypt.
func Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("bad nonce size %d", len(nonce))
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// LoadOrCreateIdentity loads an ed25519 private key from a PKCS#8 PEM file,
// creating (and persisting, mode 0600) a new one if the file is absent.
// This gives the daemon a stable Spot peer id across restarts.
func LoadOrCreateIdentity(path string) (ed25519.PrivateKey, error) {
	buf, err := os.ReadFile(path)
	if err == nil {
		blk, _ := pem.Decode(buf)
		if blk == nil {
			return nil, fmt.Errorf("identity %s: no PEM block found", path)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", path, err)
		}
		ed, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("identity %s: not an ed25519 key (%T)", path, k)
		}
		return ed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return priv, nil
}

// UploadTempFile uploads data to Util/TempFile:upload through the Spot
// client (so the API call itself is authenticated/E2E; the blob is not,
// hence callers encrypt it first) and returns its public download URL.
func UploadTempFile(ctx context.Context, sc rest.SpotClient, name string, data []byte) (string, error) {
	param := rest.Param{
		"filename":     name,
		"lastModified": time.Now().UnixMilli(),
	}
	resp, err := rest.SpotUpload(ctx, sc, "Util/TempFile:upload", "POST", param,
		bytes.NewReader(data), "application/octet-stream")
	if err != nil {
		return "", fmt.Errorf("tempfile upload failed: %w", err)
	}
	// Util/TempFile:upload returns the public download URL in "Url".
	if u, err := resp.GetString("Url"); err == nil && isHTTPURL(u) {
		return u, nil
	}
	// Fallback: scan the decoded response for any http(s) URL.
	val, err := resp.Value()
	if err != nil {
		return "", fmt.Errorf("tempfile upload: bad response: %w", err)
	}
	if u := findURL(val); u != "" {
		return u, nil
	}
	return "", fmt.Errorf("tempfile upload: no download URL in response: %#v", val)
}

// findURL walks an arbitrary decoded-JSON value and returns the first
// http(s) string it finds, preferring keys that look URL-ish.
func findURL(v any) string {
	if s := findURLPref(v, true); s != "" {
		return s
	}
	return findURLPref(v, false)
}

func findURLPref(v any, preferKey bool) string {
	switch t := v.(type) {
	case map[string]any:
		if preferKey {
			for k, sv := range t {
				lk := strings.ToLower(k)
				if strings.Contains(lk, "url") || strings.Contains(lk, "link") {
					if s, ok := sv.(string); ok && isHTTPURL(s) {
						return s
					}
				}
			}
		}
		for _, sv := range t {
			if s := findURLPref(sv, preferKey); s != "" {
				return s
			}
		}
	case []any:
		for _, sv := range t {
			if s := findURLPref(sv, preferKey); s != "" {
				return s
			}
		}
	case string:
		if !preferKey && isHTTPURL(t) {
			return t
		}
	}
	return ""
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "https://") || strings.HasPrefix(s, "http://")
}

// DownloadURL fetches the (encrypted) blob at url over plain HTTPS,
// following redirects. The payload is AES-encrypted so the transport
// being unauthenticated/plaintext is acceptable by design.
func DownloadURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %s", url, resp.Status)
	}
	return io.ReadAll(resp.Body)
}
