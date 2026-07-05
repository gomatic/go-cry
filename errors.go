package sshage

// Imported bare (the package is named error); this file declares only sentinels
// and uses no builtin error type, so the declaration reads errs.Const. The
// mechanism (the Const type and its With wrapper) is owned by go-error; this
// package declares only its own error values.
import errs "github.com/gomatic/go-error"

const (
	// ErrEncrypt is the leading sentinel wrapped when age encryption fails.
	ErrEncrypt errs.Const = "failed to encrypt"
	// ErrDecrypt is the leading sentinel wrapped when age decryption fails.
	ErrDecrypt errs.Const = "failed to decrypt"
	// ErrOpenFile is the leading sentinel wrapped when an identity file cannot
	// be read.
	ErrOpenFile errs.Const = "failed to open file"
	// ErrParseIdentity is the leading sentinel wrapped when an SSH private key
	// cannot be parsed into an age identity.
	ErrParseIdentity errs.Const = "failed to parse identity"
)
