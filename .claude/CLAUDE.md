# go-cry

Stream encryption with [age](https://age-encryption.org), keyed by SSH keys: `Encrypt`/`Decrypt` (age recipients/identities) and `ParseIdentities` (SSH private key → age identities). Extracted from `gomatic/ssh-tgzx`'s `internal/crypt`.

- Package `sshage` (repo `go-cry`), over `filippo.io/age` + `filippo.io/age/agessh` (`golang.org/x/crypto` is a test-only dep). Every failure wraps a sentinel `Error` const (`ErrEncrypt`, `ErrDecrypt`, `ErrOpenFile`, `ErrParseIdentity`) matchable with `errors.Is`.
- Gate: gofumpt, vet, staticcheck, govulncheck, gocognit ≤ 7, 100% coverage. Shared config (`Makefile`, `.golangci.yaml`, `.github/`, …) is owned by `nicerobot/tools.repository` — never edit in-tree; use `Makefile.local`.
