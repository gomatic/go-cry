package sshage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSentinels verifies each sentinel's contract: its constant text, that it
// matches itself under errors.Is, and that no two sentinels match each other.
func TestSentinels(t *testing.T) {
	t.Parallel()

	sentinels := []struct {
		wantErr  error
		name     string
		wantText string
	}{
		{name: "encrypt", wantErr: ErrEncrypt, wantText: "failed to encrypt"},
		{name: "decrypt", wantErr: ErrDecrypt, wantText: "failed to decrypt"},
		{name: "open file", wantErr: ErrOpenFile, wantText: "failed to open file"},
		{name: "parse identity", wantErr: ErrParseIdentity, wantText: "failed to parse identity"},
	}

	for i, tt := range sentinels {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want := assert.New(t)

			want.Equal(tt.wantText, tt.wantErr.Error())
			want.ErrorIs(tt.wantErr, tt.wantErr)

			// Distinct sentinels never match each other.
			for j, other := range sentinels {
				if j != i {
					want.NotErrorIs(tt.wantErr, other.wantErr)
				}
			}
		})
	}
}

// TestSentinels_With verifies the sentinels compose with errs.Const.With: the
// sentinel and the cause both stay recoverable from the wrapped chain.
func TestSentinels_With(t *testing.T) {
	t.Parallel()
	must := require.New(t)

	cause := errors.New("root cause")

	got := ErrOpenFile.With(cause, "path/to/file")
	must.ErrorIs(got, ErrOpenFile)
	must.ErrorIs(got, cause)
	must.NotErrorIs(got, ErrDecrypt)
}
