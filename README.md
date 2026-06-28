# go-cry

Stream encryption and decryption with [age](https://age-encryption.org), keyed by SSH keys. `Encrypt` seals data for a set of age recipients (an SSH public key becomes a recipient via `filippo.io/age/agessh`); `Decrypt` reverses it with age identities; `ParseIdentities` loads age identities from an SSH private-key file. Works over any `io.Reader`/`io.Writer` and reports every failure as a sentinel matchable with `errors.Is`.

## Install

```sh
go get github.com/gomatic/go-cry
```

## Usage

```go
package main

import (
	"bytes"
	"fmt"

	"filippo.io/age/agessh"
	sshage "github.com/gomatic/go-cry"
)

func main() {
	// A GitHub-style SSH public key becomes an age recipient.
	rcpt, err := agessh.ParseRecipient("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...")
	if err != nil {
		panic(err)
	}

	var sealed bytes.Buffer
	if err := sshage.Encrypt(&sealed, bytes.NewReader([]byte("secret")), nil /* []age.Recipient{rcpt} */); err != nil {
		panic(err)
	}

	// Decrypt with identities loaded from an SSH private key.
	ids, err := sshage.ParseIdentities("/home/user/.ssh/id_ed25519")
	if err != nil {
		panic(err)
	}
	var clear bytes.Buffer
	if err := sshage.Decrypt(&clear, &sealed, ids); err != nil {
		panic(err)
	}
	fmt.Println(clear.String())
	_ = rcpt
}
```

## Errors

Every failure wraps one of the package sentinels, recoverable with `errors.Is`: `sshage.ErrEncrypt`, `sshage.ErrDecrypt`, `sshage.ErrOpenFile`, `sshage.ErrParseIdentity`.

## Build & test

The `Makefile`, `.golangci.yaml`, `.editorconfig`, `.gitignore`, and `.github/` are the canonical gomatic Go toolchain, owned and distributed by [`nicerobot/tools.repository`](https://github.com/nicerobot/tools.repository) — do not edit them in-tree; per-repo changes belong in a `Makefile.local`. Run the full gate (lint, staticcheck, govulncheck, 100% coverage) with `make check`.
