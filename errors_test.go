package sshage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestError_Error(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "failed to decrypt", ErrDecrypt.Error())
}

func TestError_Wrap(t *testing.T) {
	t.Parallel()

	cause := errors.New("root cause")

	tests := []struct {
		err         error
		name        string
		wantMessage string
		args        []any
		wantCause   bool
	}{
		{
			name:        "no args no cause returns the bare sentinel",
			wantMessage: "failed to encrypt",
		},
		{
			name:        "args only",
			args:        []any{"path/to/file"},
			wantMessage: "failed to encrypt: path/to/file",
		},
		{
			name:        "cause only",
			err:         cause,
			wantMessage: "failed to encrypt: root cause",
			wantCause:   true,
		},
		{
			name:        "args and cause",
			args:        []any{"path/to/file"},
			err:         cause,
			wantMessage: "failed to encrypt: path/to/file: root cause",
			wantCause:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			want, must := assert.New(t), require.New(t)

			got := ErrEncrypt.Wrap(tt.err, tt.args...)
			must.Error(got)

			want.Equal(tt.wantMessage, got.Error())
			// The sentinel is always recoverable from the chain.
			want.ErrorIs(got, ErrEncrypt)
			// A different sentinel must not match.
			want.NotErrorIs(got, ErrDecrypt)

			if tt.wantCause {
				want.ErrorIs(got, cause)
			}
		})
	}
}
