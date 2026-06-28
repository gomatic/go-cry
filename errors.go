package sshage

import "fmt"

// Error is sshage's sentinel-error type. Every error the package can emit is
// declared as a const of this type, so each one is matchable with errors.Is
// rather than by string comparison. It follows the same shape as the rest of
// the ecosystem's sentinel-error helpers.
type Error string

// Error returns the constant's text, implementing the error interface.
func (e Error) Error() string { return string(e) }

var _ error = Error("")

// Wrap returns an error that always carries the sentinel e in its chain (so
// errors.Is(result, e) holds), optionally annotated with context args and a
// wrapped cause. The sentinel e itself is preserved unchanged in the chain;
// context is added as a separate message layer so identity is never lost.
func (e Error) Wrap(err error, args ...any) error {
	switch {
	case len(args) > 0 && err != nil:
		return fmt.Errorf("%w: %s: %w", e, fmt.Sprint(args...), err)
	case len(args) > 0:
		return fmt.Errorf("%w: %s", e, fmt.Sprint(args...))
	case err != nil:
		return fmt.Errorf("%w: %w", e, err)
	default:
		return e
	}
}

const (
	// ErrEncrypt is the leading sentinel wrapped when age encryption fails.
	ErrEncrypt Error = "failed to encrypt"
	// ErrDecrypt is the leading sentinel wrapped when age decryption fails.
	ErrDecrypt Error = "failed to decrypt"
	// ErrOpenFile is the leading sentinel wrapped when an identity file cannot
	// be read.
	ErrOpenFile Error = "failed to open file"
	// ErrParseIdentity is the leading sentinel wrapped when an SSH private key
	// cannot be parsed into an age identity.
	ErrParseIdentity Error = "failed to parse identity"
)
