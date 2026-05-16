# gosigner

Remote [Microsoft Authenticode](https://learn.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools) signing for Windows PE files (`.exe`, `.dll`) over the [Spot](https://pkg.go.dev/github.com/KarpelesLab/spotlib) end-to-end-encrypted network. A USB code-signing token lives on one trusted machine; developers anywhere sign without ever holding the PIN or the certificate.

Everything is pure Go. No `osslsigncode`, no PKCS#11 engine, no closed-source vendor library — `pcscd` (open-source pcsc-lite) is the only system service required on the daemon host.

## How it works

```
┌──────────────────────┐                          ┌────────────────────────┐
│ developer machine    │   Util/TempFile          │ daemon (token holder)  │
│                      │ ←────  blob store  ─→    │                        │
│ signreq:             │                          │ gosigner:              │
│ • AES-256-GCM encrypt│                          │ • verify shared secret │
│ • upload ciphertext  │                          │ • download + decrypt   │
│ • Query peer/sign ───┼──── E2E Spot message ───→│ • authenticode.Sign    │
│ • download reply     │                          │   driven by hsm.Key    │
│ • decrypt + write    │←──── E2E Spot reply ─────│ • re-encrypt + upload  │
└──────────────────────┘                          └────────────────────────┘
                                                            │
                                                            ▼ APDUs over pcscd
                                                  ┌────────────────────────┐
                                                  │ USB token (eToken etc.)│
                                                  └────────────────────────┘
```

Spot messages are E2E encrypted by `spotlib`; blob payloads on `Util/TempFile` are independently AES-256-GCM encrypted with a per-transfer key carried inside the Spot message. The daemon authorizes by a shared secret (constant-time compared), not by the client's identity. Clients use an ephemeral Spot key.

Signing uses [`github.com/KarpelesLab/authenticode`](https://github.com/KarpelesLab/authenticode) for the PE + CMS + RFC 3161 path and [`github.com/KarpelesLab/hsm`](https://github.com/KarpelesLab/hsm) (`HSM=idprime`) to drive the USB token over pcsc-lite's Unix socket. The plaintext binary never touches the daemon's disk.

## Client (developer side)

No clone, no install:

```sh
go run github.com/KarpelesLab/gosigner/cli/signreq@latest \
    -peer   k.PEER-ID-FROM-DAEMON \
    -secret "shared-secret" \
    -o      mybinary.signed.exe \
    mybinary.exe
```

The client picks an ephemeral Spot identity, encrypts the binary, hands it to the daemon over Spot, and writes the signed result.

## Daemon (token side)

The host that physically holds the token runs:

```sh
HSM=idprime IDPRIME_PIN='<token-pin>' gosigner \
    -identity ./gosigner.key \
    -secret   '<shared-secret>'
```

On first launch it generates `./gosigner.key` (an ed25519 PKCS#8 PEM, mode 0600) and prints its **peer id** (`k.…`). The peer id is stable across restarts as long as that key file is kept. Hand the peer id + shared secret to the developers who need to sign.

The signing certificate, certificate chain, key reference, and algorithm OID are all discovered automatically from the card — no `-cert`, `-key-id`, or `-pkcs11-module` flags. The PIN goes through `IDPRIME_PIN` (env) so it stays out of `ps` / shell history.

### Daemon flags

| Flag | Env | Default | Notes |
|------|-----|---------|-------|
| `-identity` | `GOSIGNER_IDENTITY` | `./gosigner.key` | ed25519 Spot identity (created if absent) |
| `-secret` | `GOSIGNER_SECRET` | _(required)_ | Shared secret clients must present |
| `-key-cn` | `GOSIGNER_KEY_CN` | _(none)_ | Optional Subject.CN filter when the card carries multiple keys |
| `-timestamp-url` | `GOSIGNER_TIMESTAMP_URL` | `http://timestamp.digicert.com` | RFC 3161 TSA; empty disables timestamping |
| `-hash` | `GOSIGNER_HASH` | `sha384` | `sha256` / `sha384` / `sha512` |
| `-endpoint` | `GOSIGNER_ENDPOINT` | `sign` | Spot endpoint name |

The HSM is selected via the `HSM` env var (defaults to `idprime`); the IDPrime backend reads `IDPRIME_PIN`, `IDPRIME_READER`, etc. — see [`KarpelesLab/hsm`](https://github.com/KarpelesLab/hsm).

## What the daemon ever writes to disk

Just the ed25519 identity (`./gosigner.key`, one-time on first launch). The binary being signed, the cert chain, the PIN, and the AES keys are kept only in memory. Token I/O is via the pcsc-lite Unix socket; signing runs in-process.

## Verifying a signed binary

Any Authenticode verifier works — for example:

```sh
osslsigncode verify -in mybinary.signed.exe
```

## License

See `LICENSE`.
