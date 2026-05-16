// Command signreq is the client side of the remote Authenticode signer.
//
// It encrypts a local .exe/.dll, uploads the ciphertext to Util/TempFile
// (through Spot), then asks a gosigner daemon (addressed by its ed25519
// peer id, authorized by a shared secret) to sign it. The signed result
// comes back the same way and is written to a new file; the input is
// left untouched.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KarpelesLab/gosigner/internal/proto"
	"github.com/KarpelesLab/spotlib"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("signreq: ")

	peer := flag.String("peer", os.Getenv("GOSIGNER_PEER"), "daemon Spot peer id, k.… (required) [GOSIGNER_PEER]")
	secret := flag.String("secret", os.Getenv("GOSIGNER_SECRET"), "shared secret (required) [GOSIGNER_SECRET]")
	out := flag.String("o", "", "output path (default <name>.signed<ext>)")
	endpoint := flag.String("endpoint", env("GOSIGNER_ENDPOINT", proto.Endpoint), "Spot endpoint name on the daemon")
	timeout := flag.Duration("timeout", 5*time.Minute, "overall timeout")
	programName := flag.String("name", "", "program name embedded in SpcSpOpusInfo (signtool /d, osslsigncode -n)")
	programURL := flag.String("url", "", "program URL embedded in SpcSpOpusInfo (signtool /du, osslsigncode -i)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: signreq [flags] <input.exe>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	input := flag.Arg(0)
	if *peer == "" {
		log.Fatal("missing -peer (or GOSIGNER_PEER)")
	}
	if *secret == "" {
		log.Fatal("missing -secret (or GOSIGNER_SECRET)")
	}
	if !strings.HasPrefix(*peer, "k.") {
		log.Fatalf("invalid -peer %q: expected a k.… spot id", *peer)
	}

	outPath := *out
	if outPath == "" {
		ext := filepath.Ext(input)
		outPath = strings.TrimSuffix(input, ext) + ".signed" + ext
	}

	data, err := os.ReadFile(input)
	if err != nil {
		log.Fatalf("read %s: %v", input, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	// Ephemeral Spot identity: the daemon authorizes by shared secret,
	// not by who we are, so there is no client key to manage.
	client, err := spotlib.New()
	if err != nil {
		log.Fatalf("spot client: %v", err)
	}
	defer client.Close()
	if err := client.WaitOnline(ctx); err != nil {
		log.Fatalf("connect to spot: %v", err)
	}

	ct, key, nonce, err := proto.Encrypt(data)
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	name := filepath.Base(input)
	url, err := proto.UploadTempFile(ctx, client, name, ct)
	if err != nil {
		log.Fatalf("upload: %v", err)
	}

	reqBody, err := json.Marshal(proto.SignRequest{
		Secret:      *secret,
		URL:         url,
		Key:         key,
		Nonce:       nonce,
		Filename:    name,
		ProgramName: *programName,
		ProgramURL:  *programURL,
	})
	if err != nil {
		log.Fatalf("marshal request: %v", err)
	}

	log.Printf("requesting signature from %s …", *peer)
	respBody, err := client.Query(ctx, *peer+"/"+*endpoint, reqBody)
	if err != nil {
		log.Fatalf("sign request failed: %v", err)
	}

	var resp proto.SignResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		log.Fatalf("invalid response: %v", err)
	}
	signedCT, err := proto.DownloadURL(ctx, resp.URL)
	if err != nil {
		log.Fatalf("download signed file: %v", err)
	}
	signed, err := proto.Decrypt(signedCT, resp.Key, resp.Nonce)
	if err != nil {
		log.Fatalf("decrypt signed file: %v", err)
	}
	if err := os.WriteFile(outPath, signed, 0o644); err != nil {
		log.Fatalf("write %s: %v", outPath, err)
	}
	log.Printf("signed binary written to %s (%d bytes)", outPath, len(signed))
}
