package sshage

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func generateEd25519Identity(t *testing.T) (age.Identity, age.Recipient, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(pub)
	require.NoError(t, err)

	rcpt, err := agessh.ParseRecipient(string(ssh.MarshalAuthorizedKey(sshPub)))
	require.NoError(t, err)

	privKey, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	id, err := agessh.ParseIdentity(pem.EncodeToMemory(privKey))
	require.NoError(t, err)

	return id, rcpt, pem.EncodeToMemory(privKey)
}

func generateRSAIdentity(t *testing.T) (age.Identity, age.Recipient) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	sshPub, err := ssh.NewPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	rcpt, err := agessh.ParseRecipient(string(ssh.MarshalAuthorizedKey(sshPub)))
	require.NoError(t, err)

	privKey, err := ssh.MarshalPrivateKey(priv, "")
	require.NoError(t, err)

	id, err := agessh.ParseIdentity(pem.EncodeToMemory(privKey))
	require.NoError(t, err)

	return id, rcpt
}

func TestEncryptDecrypt_Ed25519(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	id, rcpt, _ := generateEd25519Identity(t)

	plaintext := []byte("secret data for ed25519")

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader(plaintext), Recipients{rcpt}))

	var decrypted bytes.Buffer
	must.NoError(Decrypt(&decrypted, &encrypted, Identities{id}))

	want.Equal(plaintext, decrypted.Bytes())
}

func TestEncryptDecrypt_RSA(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	id, rcpt := generateRSAIdentity(t)

	plaintext := []byte("secret data for rsa")

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader(plaintext), Recipients{rcpt}))

	var decrypted bytes.Buffer
	must.NoError(Decrypt(&decrypted, &encrypted, Identities{id}))

	want.Equal(plaintext, decrypted.Bytes())
}

func TestDecrypt_WrongKey(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, rcpt1, _ := generateEd25519Identity(t)
	id2, _, _ := generateEd25519Identity(t)

	plaintext := []byte("wrong key test")

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader(plaintext), Recipients{rcpt1}))

	var decrypted bytes.Buffer
	err := Decrypt(&decrypted, &encrypted, Identities{id2})
	must.ErrorIs(err, ErrDecrypt)
}

func TestDecrypt_Tampered(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	id, rcpt, _ := generateEd25519Identity(t)

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader([]byte("authenticated payload")), Recipients{rcpt}))

	// age is authenticated encryption: flipping a single ciphertext byte must
	// fail the integrity check rather than yield altered plaintext. Flip the
	// final byte, which lands in the payload's authentication tag.
	ciphertext := encrypted.Bytes()
	ciphertext[len(ciphertext)-1] ^= 0xff

	var decrypted bytes.Buffer
	err := Decrypt(&decrypted, bytes.NewReader(ciphertext), Identities{id})
	must.ErrorIs(err, ErrDecrypt)
}

func TestEncryptDecrypt_MultipleRecipients(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	id1, rcpt1, _ := generateEd25519Identity(t)
	id2, rcpt2 := generateRSAIdentity(t)

	plaintext := []byte("multi-recipient secret")

	// Encrypt for both recipients
	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader(plaintext), Recipients{rcpt1, rcpt2}))

	// Either identity should be able to decrypt.
	encrypted1 := bytes.NewBuffer(encrypted.Bytes())
	encrypted2 := bytes.NewBuffer(encrypted.Bytes())

	var dec1 bytes.Buffer
	must.NoError(Decrypt(&dec1, encrypted1, Identities{id1}))
	want.Equal(plaintext, dec1.Bytes())

	var dec2 bytes.Buffer
	must.NoError(Decrypt(&dec2, encrypted2, Identities{id2}))
	want.Equal(plaintext, dec2.Bytes())
}

func TestParseIdentities(t *testing.T) {
	t.Parallel()
	want, must := assert.New(t), require.New(t)

	_, rcpt, privPEM := generateEd25519Identity(t)

	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	must.NoError(os.WriteFile(keyFile, privPEM, 0o600))

	ids, err := ParseIdentities(IdentityFile(keyFile))
	must.NoError(err)
	must.Len(ids, 1)

	// The parsed identity must actually unseal data sealed to its matching
	// SSH recipient: encrypt to rcpt, then round-trip through the loaded ids.
	plaintext := []byte("parsed identity round-trip")

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader(plaintext), Recipients{rcpt}))

	var decrypted bytes.Buffer
	must.NoError(Decrypt(&decrypted, &encrypted, ids))
	want.Equal(plaintext, decrypted.Bytes())
}

func TestParseIdentities_Nonexistent(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, err := ParseIdentities("/nonexistent/path/id_ed25519")
	must.ErrorIs(err, ErrOpenFile)
}

func TestParseIdentities_BadKey(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	keyFile := filepath.Join(t.TempDir(), "id_bad")
	must.NoError(os.WriteFile(keyFile, []byte("not a valid ssh key"), 0o600))

	_, err := ParseIdentities(IdentityFile(keyFile))
	must.ErrorIs(err, ErrParseIdentity)
}

// failWriter fails every write, exercising encrypt/decrypt copy error paths.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errBoom }

// failReader fails every read.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errBoom }

var errBoom = errorString("boom")

type errorString string

func (e errorString) Error() string { return string(e) }

func TestEncrypt_NoRecipients(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	var buf bytes.Buffer
	err := Encrypt(&buf, bytes.NewReader([]byte("data")), nil)
	must.ErrorIs(err, ErrEncrypt)
}

func TestEncrypt_CopyError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, rcpt, _ := generateEd25519Identity(t)
	err := Encrypt(&bytes.Buffer{}, failReader{}, Recipients{rcpt})
	must.ErrorIs(err, ErrEncrypt)
}

func TestEncrypt_WriterError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, rcpt, _ := generateEd25519Identity(t)
	// age.Encrypt writes a header immediately; a failing writer surfaces there.
	err := Encrypt(failWriter{}, bytes.NewReader([]byte("data")), Recipients{rcpt})
	must.ErrorIs(err, ErrEncrypt)
}

// budgetWriter accepts up to budget bytes, then fails. It lets the age header
// (written by age.Encrypt) through while forcing the final flush in Close to
// fail, exercising Encrypt's ew.Close() error path.
type budgetWriter struct {
	budget int
	used   int
}

func (w *budgetWriter) Write(p []byte) (int, error) {
	if w.used+len(p) > w.budget {
		return 0, errBoom
	}
	w.used += len(p)
	return len(p), nil
}

func TestEncrypt_CloseError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	_, rcpt, _ := generateEd25519Identity(t)
	// 200 bytes covers the ed25519 age header but not the ciphertext flush.
	err := Encrypt(&budgetWriter{budget: 200}, bytes.NewReader([]byte("payload")), Recipients{rcpt})
	must.ErrorIs(err, ErrEncrypt)
}

func TestDecrypt_WriterError(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	id, rcpt, _ := generateEd25519Identity(t)

	var encrypted bytes.Buffer
	must.NoError(Encrypt(&encrypted, bytes.NewReader([]byte("secret")), Recipients{rcpt}))

	err := Decrypt(failWriter{}, &encrypted, Identities{id})
	must.ErrorIs(err, ErrDecrypt)
}
