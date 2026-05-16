// Command gosigner is the daemon side of the remote Authenticode signer.
//
// It holds a static ed25519 Spot identity (so its peer id is stable) and
// the USB code-signing token. It listens on the Spot network for sign
// requests carrying a shared secret, downloads the caller's encrypted
// binary from Util/TempFile, signs it with osslsigncode via the opensc
// PKCS#11 module, re-encrypts the result, uploads it back and replies
// with the new location + key over the end-to-end-encrypted Spot channel.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/KarpelesLab/gosigner/internal/proto"
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
	cert         string
	pkcs11Cert   string
	pkcs11Module string
	pkcs11Engine string
	keyID        string
	pin          string
	timestampURL string
	hash         string
	endpoint     string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("gosigner: ")

	cfg := &config{}
	flag.StringVar(&cfg.identity, "identity", env("GOSIGNER_IDENTITY", "./gosigner.key"), "path to the static ed25519 identity (PKCS#8 PEM, created if absent) [GOSIGNER_IDENTITY]")
	flag.StringVar(&cfg.secret, "secret", os.Getenv("GOSIGNER_SECRET"), "shared secret required from clients (required) [GOSIGNER_SECRET]")
	flag.StringVar(&cfg.cert, "cert", os.Getenv("GOSIGNER_CERT"), "signing certificate chain, PEM file (required) [GOSIGNER_CERT]")
	flag.StringVar(&cfg.pkcs11Cert, "pkcs11-cert", os.Getenv("GOSIGNER_PKCS11_CERT"), "optional PKCS#11 URI of the certificate in the token (passed as -pkcs11cert)")
	flag.StringVar(&cfg.pkcs11Module, "pkcs11-module", env("GOSIGNER_PKCS11_MODULE", "/usr/lib64/opensc-pkcs11.so"), "PKCS#11 module path")
	flag.StringVar(&cfg.pkcs11Engine, "pkcs11-engine", os.Getenv("GOSIGNER_PKCS11_ENGINE"), "optional PKCS#11 engine path (passed as -pkcs11engine)")
	flag.StringVar(&cfg.keyID, "key-id", os.Getenv("GOSIGNER_KEY_ID"), "PKCS#11 key id/label or full pkcs11: URI of the signing key (required) [GOSIGNER_KEY_ID]")
	flag.StringVar(&cfg.pin, "pin", os.Getenv("GOSIGNER_PIN"), "token PIN [GOSIGNER_PIN]")
	flag.StringVar(&cfg.timestampURL, "timestamp-url", env("GOSIGNER_TIMESTAMP_URL", "http://timestamp.digicert.com"), "RFC3161 Time-Stamp Authority URL (empty to disable)")
	flag.StringVar(&cfg.hash, "hash", env("GOSIGNER_HASH", "sha256"), "digest algorithm: md5|sha1|sha256|sha384|sha512")
	flag.StringVar(&cfg.endpoint, "endpoint", env("GOSIGNER_ENDPOINT", proto.Endpoint), "Spot endpoint name to listen on")
	flag.Parse()

	if cfg.secret == "" {
		log.Fatal("missing -secret (or GOSIGNER_SECRET)")
	}
	if cfg.cert == "" {
		log.Fatal("missing -cert (or GOSIGNER_CERT)")
	}
	if cfg.keyID == "" {
		log.Fatal("missing -key-id (or GOSIGNER_KEY_ID)")
	}

	// Fail fast on missing tooling / files so the operator gets a clear
	// message instead of a cryptic failure on the first request.
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		log.Fatal("osslsigncode not found in PATH; install it (e.g. your distro's osslsigncode package)")
	}
	if _, err := os.Stat(cfg.cert); err != nil {
		log.Fatalf("certificate %s: %v", cfg.cert, err)
	}
	if _, err := os.Stat(cfg.pkcs11Module); err != nil {
		log.Fatalf("pkcs11 module %s: %v", cfg.pkcs11Module, err)
	}

	idKey, err := proto.LoadOrCreateIdentity(cfg.identity)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}

	client, err := spotlib.New(idKey, map[string]string{"app": "gosigner"})
	if err != nil {
		log.Fatalf("spot client: %v", err)
	}
	defer client.Close()

	s := &signer{cfg: cfg, client: client}
	client.SetHandler(cfg.endpoint, s.handle)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := client.WaitOnline(ctx); err != nil {
		log.Fatalf("could not connect to spot: %v", err)
	}

	log.Printf("online. peer id (give this to signreq --peer):")
	fmt.Println(client.TargetId())
	log.Printf("listening for sign requests on endpoint %q", cfg.endpoint)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
}

type signer struct {
	cfg    *config
	client *spotlib.Client
	mu     sync.Mutex // serialize token access (one PKCS#11 session at a time)
}

// handle processes one decrypted, signature-verified Spot message.
// Returning an error sends it back to the caller as an error reply.
func (s *signer) handle(msg *spotproto.Message) ([]byte, error) {
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

	signed, err := s.sign(ctx, name, plain)
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

// sign writes the binary to a private temp dir, runs osslsigncode against
// the PKCS#11 token, and returns the signed bytes.
func (s *signer) sign(ctx context.Context, name string, data []byte) ([]byte, error) {
	dir, err := os.MkdirTemp("", "gosigner-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	inPath := filepath.Join(dir, "in-"+name)
	outPath := filepath.Join(dir, "out-"+name)
	if err := os.WriteFile(inPath, data, 0o600); err != nil {
		return nil, err
	}

	args := []string{"sign"}
	if s.cfg.pkcs11Engine != "" {
		args = append(args, "-pkcs11engine", s.cfg.pkcs11Engine)
	}
	args = append(args, "-pkcs11module", s.cfg.pkcs11Module, "-login")
	if s.cfg.pkcs11Cert != "" {
		args = append(args, "-pkcs11cert", s.cfg.pkcs11Cert)
	}
	args = append(args,
		"-certs", s.cfg.cert,
		"-key", s.cfg.keyID,
		"-h", s.cfg.hash,
	)
	if s.cfg.timestampURL != "" {
		args = append(args, "-ts", s.cfg.timestampURL)
	}
	// PIN via a 0600 file inside the per-request temp dir so it never
	// appears in argv / ps output.
	if s.cfg.pin != "" {
		pinPath := filepath.Join(dir, "pin")
		if err := os.WriteFile(pinPath, []byte(s.cfg.pin+"\n"), 0o600); err != nil {
			return nil, err
		}
		args = append(args, "-readpass", pinPath)
	}
	args = append(args, "-in", inPath, "-out", outPath)

	// One token session at a time.
	s.mu.Lock()
	defer s.mu.Unlock()

	cmd := exec.CommandContext(ctx, "osslsigncode", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("osslsigncode: %v: %s", err, out)
	}
	return os.ReadFile(outPath)
}
