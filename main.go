// Command gosigner is the daemon side of the remote Authenticode signer.
//
// It holds a static ed25519 Spot identity (so its peer id is stable) and
// the USB code-signing token. It listens on the Spot network for sign
// requests carrying a shared secret, downloads the caller's encrypted
// binary from Util/TempFile, signs it natively in Go via the
// github.com/KarpelesLab/authenticode and github.com/KarpelesLab/hsm
// libraries (no osslsigncode, no PKCS#11 engine, no closed library),
// re-encrypts the result, uploads it back, and replies with the new
// location + AES key over the end-to-end-encrypted Spot channel.
package main

import (
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/KarpelesLab/authenticode"
	"github.com/KarpelesLab/gosigner/internal/proto"
	"github.com/KarpelesLab/hsm"
	"github.com/KarpelesLab/spotlib"
	"github.com/KarpelesLab/spotproto"
)

// env returns the environment variable value or def if unset/empty.
func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type config struct {
	identity     string
	secret       string
	keyCN        string
	timestampURL string
	hashName     string
	endpoint     string
	hash         crypto.Hash
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("gosigner: ")

	cfg := &config{}
	flag.StringVar(&cfg.identity, "identity", env("GOSIGNER_IDENTITY", "./gosigner.key"), "path to the static ed25519 Spot identity (PKCS#8 PEM, created if absent) [GOSIGNER_IDENTITY]")
	flag.StringVar(&cfg.secret, "secret", os.Getenv("GOSIGNER_SECRET"), "shared secret required from clients (required) [GOSIGNER_SECRET]")
	flag.StringVar(&cfg.keyCN, "key-cn", os.Getenv("GOSIGNER_KEY_CN"), "optional Subject.CommonName to filter the HSM key (default: first enumerated key)")
	flag.StringVar(&cfg.timestampURL, "timestamp-url", env("GOSIGNER_TIMESTAMP_URL", "http://timestamp.digicert.com"), "RFC3161 Time-Stamp Authority URL (empty to disable)")
	flag.StringVar(&cfg.hashName, "hash", env("GOSIGNER_HASH", "sha384"), "digest algorithm: sha256|sha384|sha512")
	flag.StringVar(&cfg.endpoint, "endpoint", env("GOSIGNER_ENDPOINT", proto.Endpoint), "Spot endpoint name to listen on")
	flag.Parse()

	if cfg.secret == "" {
		log.Fatal("missing -secret (or GOSIGNER_SECRET)")
	}
	switch cfg.hashName {
	case "sha256":
		cfg.hash = crypto.SHA256
	case "sha384":
		cfg.hash = crypto.SHA384
	case "sha512":
		cfg.hash = crypto.SHA512
	default:
		log.Fatalf("unsupported -hash %q (want sha256|sha384|sha512)", cfg.hashName)
	}

	// Load (or generate) the static ed25519 identity used by Spot.
	idKey, err := proto.LoadOrCreateIdentity(cfg.identity)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	// Connect to the HSM (selected via the HSM env var — typically
	// "idprime" for a USB token). The library prompts for the PIN on
	// tty if IDPRIME_PIN is unset.
	if os.Getenv("HSM") == "" {
		_ = os.Setenv("HSM", "idprime")
	}
	h, err := hsm.New()
	if err != nil {
		log.Fatalf("hsm: %v", err)
	}

	keys, err := h.ListKeysByName(cfg.keyCN)
	if err != nil {
		log.Fatalf("list keys: %v", err)
	}
	if len(keys) == 0 {
		log.Fatal("no usable keys on the token (cert expired, RSA-only, or filter mismatch)")
	}
	key := keys[0]
	signer, ok := key.(authenticode.Signer)
	if !ok {
		log.Fatalf("hsm key %s does not implement authenticode.Signer", key)
	}
	log.Printf("signing key: %s", key)

	client, err := spotlib.New(idKey, map[string]string{"app": "gosigner"})
	if err != nil {
		log.Fatalf("spot client: %v", err)
	}
	defer client.Close()

	s := &signerSrv{cfg: cfg, client: client, signer: signer}
	client.SetHandler(cfg.endpoint, s.handle)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := client.WaitOnline(ctx); err != nil {
		log.Fatalf("could not connect to spot: %v", err)
	}

	log.Printf("online. peer id (give this to signreq -peer):")
	fmt.Println(client.TargetId())
	log.Printf("listening for sign requests on endpoint %q", cfg.endpoint)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
}

type signerSrv struct {
	cfg    *config
	client *spotlib.Client
	signer authenticode.Signer
	mu     sync.Mutex // one token session at a time
}

// handle processes one decrypted, signature-verified Spot message.
// Returning an error sends it back to the caller as an error reply.
func (s *signerSrv) handle(msg *spotproto.Message) ([]byte, error) {
	if !msg.IsEncrypted() {
		return nil, fmt.Errorf("request must be end-to-end encrypted")
	}

	var req proto.SignRequest
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(s.cfg.secret)) != 1 {
		log.Printf("rejected request from %s: bad shared secret", msg.Sender)
		return nil, fmt.Errorf("unauthorized: bad shared secret")
	}

	name := filepath.Base(req.Filename)
	if name == "" || name == "." || name == "/" {
		name = "input.exe"
	}
	log.Printf("sign request from %s: %s", msg.Sender, name)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	blob, err := proto.DownloadURL(ctx, req.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch source: %w", err)
	}
	plain, err := proto.Decrypt(blob, req.Key, req.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decrypt source: %w", err)
	}

	signed, err := s.sign(ctx, plain)
	if err != nil {
		log.Printf("signing %s failed: %v", name, err)
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	ct, key, nonce, err := proto.Encrypt(signed)
	if err != nil {
		return nil, fmt.Errorf("encrypt result: %w", err)
	}
	url, err := proto.UploadTempFile(ctx, s.client, name, ct)
	if err != nil {
		return nil, fmt.Errorf("upload result: %w", err)
	}

	resp, err := json.Marshal(proto.SignResponse{
		URL:      url,
		Key:      key,
		Nonce:    nonce,
		Filename: name,
	})
	if err != nil {
		return nil, err
	}
	log.Printf("signed %s -> %s", name, url)
	return resp, nil
}

// sign produces an Authenticode signature over the PE bytes using the
// on-token key, in pure Go. Token access is serialized; the HSM-side
// session/PIN is held inside the Signer.
func (s *signerSrv) sign(ctx context.Context, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return authenticode.Sign(data, s.signer, authenticode.SignOptions{
		Hash:    s.cfg.hash,
		TSAURL:  s.cfg.timestampURL,
		Context: ctx,
	})
}
