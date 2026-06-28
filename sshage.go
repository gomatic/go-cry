// Package sshage encrypts and decrypts streams with [age], keyed by SSH keys.
// Encrypt seals data from a reader to a writer for a set of age recipients (an
// SSH public key becomes a recipient via filippo.io/age/agessh); Decrypt
// reverses it with age identities; ParseIdentities loads age identities from an
// SSH private-key file. Every failure carries a sentinel ([ErrEncrypt],
// [ErrDecrypt], [ErrOpenFile], or [ErrParseIdentity]) recoverable with errors.Is.
package sshage

import (
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/agessh"
)

// Encrypt writes age-encrypted data from r to w for the given recipients.
func Encrypt(w io.Writer, r io.Reader, recipients []age.Recipient) error {
	ew, err := age.Encrypt(w, recipients...)
	if err != nil {
		return ErrEncrypt.Wrap(err)
	}
	if _, err := io.Copy(ew, r); err != nil {
		return ErrEncrypt.Wrap(err)
	}
	if err := ew.Close(); err != nil {
		return ErrEncrypt.Wrap(err)
	}
	return nil
}

// Decrypt writes age-decrypted data from r to w using the given identities.
func Decrypt(w io.Writer, r io.Reader, identities []age.Identity) error {
	dr, err := age.Decrypt(r, identities...)
	if err != nil {
		return ErrDecrypt.Wrap(err)
	}
	if _, err := io.Copy(w, dr); err != nil {
		return ErrDecrypt.Wrap(err)
	}
	return nil
}

// ParseIdentities reads an SSH private key file and returns age identities.
func ParseIdentities(path string) ([]age.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, ErrOpenFile.Wrap(err, path)
	}

	id, err := agessh.ParseIdentity(data)
	if err != nil {
		return nil, ErrParseIdentity.Wrap(err)
	}

	return []age.Identity{id}, nil
}
