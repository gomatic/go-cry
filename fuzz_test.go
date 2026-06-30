package sshage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecrypt asserts the decryptor never panics on hostile input and that any
// failure is the ErrDecrypt sentinel. A decryptor handling untrusted ciphertext
// must reject arbitrary bytes cleanly, never crash. The identity is fixed; only
// the ciphertext is fuzzed, so a matching seed may succeed while everything else
// must fail with the sentinel — never panic, never another error class.
func FuzzDecrypt(f *testing.F) {
	id, rcpt, _ := generateEd25519Identity(f)

	var sealed bytes.Buffer
	if err := Encrypt(&sealed, bytes.NewReader([]byte("fuzz seed payload")), Recipients{rcpt}); err != nil {
		f.Fatalf("seed encrypt: %v", err)
	}

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Add([]byte("not an age file at all"))
	f.Add(sealed.Bytes())

	f.Fuzz(func(t *testing.T, ciphertext []byte) {
		var out bytes.Buffer
		err := Decrypt(&out, bytes.NewReader(ciphertext), Identities{id})
		if err != nil && !errors.Is(err, ErrDecrypt) {
			t.Fatalf("Decrypt returned non-sentinel error for arbitrary input: %v", err)
		}
	})
}

// FuzzParseIdentities asserts the SSH-key parser never panics on arbitrary key
// bytes and that any failure is the ErrParseIdentity sentinel (the file always
// exists, so ErrOpenFile cannot arise). Key parsing consumes untrusted input
// and must degrade to a typed error, never a crash.
func FuzzParseIdentities(f *testing.F) {
	_, _, validPEM := generateEd25519Identity(f)

	f.Add([]byte(nil))
	f.Add([]byte{})
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte("not a key"))
	f.Add(validPEM)

	dir := f.TempDir()

	f.Fuzz(func(t *testing.T, keyBytes []byte) {
		path := filepath.Join(dir, "id_fuzz")
		if err := os.WriteFile(path, keyBytes, 0o600); err != nil {
			t.Fatalf("write key file: %v", err)
		}

		_, err := ParseIdentities(IdentityFile(path))
		if err != nil && !errors.Is(err, ErrParseIdentity) {
			t.Fatalf("ParseIdentities returned non-sentinel error for arbitrary key: %v", err)
		}
	})
}
