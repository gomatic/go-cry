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

// Recipients is the set of age recipients data is sealed to by Encrypt.
type Recipients []age.Recipient

// Identities is the set of age identities Decrypt attempts to unseal with.
type Identities []age.Identity

// Encrypt writes age-encrypted data from r to w for the given recipients.
func Encrypt(w io.Writer, r io.Reader, recipients Recipients) error {
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
func Decrypt(w io.Writer, r io.Reader, identities Identities) error {
	dr, err := age.Decrypt(r, identities...)
	if err != nil {
		return ErrDecrypt.Wrap(err)
	}
	if _, err := io.Copy(w, dr); err != nil {
		return ErrDecrypt.Wrap(err)
	}
	return nil
}

// IdentityFile is the path to an SSH private-key file that ParseIdentities
// reads age identities from.
type IdentityFile string

// ParseIdentities reads an SSH private key file and returns age identities.
func ParseIdentities(path IdentityFile) (Identities, error) {
	data, err := os.ReadFile(string(path))
	if err != nil {
		return nil, ErrOpenFile.Wrap(err, path)
	}

	id, err := agessh.ParseIdentity(data)
	if err != nil {
		return nil, ErrParseIdentity.Wrap(err)
	}

	return Identities{id}, nil
}
