// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func rotateTestRequest(id string) *fosite.Request {
	return &fosite.Request{
		ID:          id,
		Client:      &fosite.DefaultClient{ID: "client"},
		Session:     &fosite.DefaultSession{Subject: "sub"},
		RequestedAt: time.Now().UTC(),
	}
}

func TestMemoryStore_RotateRefreshToken(t *testing.T) {
	ctx := context.Background()

	t.Run("should fail for an unknown token", func(t *testing.T) {
		store := NewMemoryStore()
		err := store.RotateRefreshToken(ctx, "family-1", "unknown-signature")
		require.ErrorIs(t, err, fosite.ErrNotFound)
	})

	t.Run("should invalidate the presented generation and its access token", func(t *testing.T) {
		store := NewMemoryStore()
		req := rotateTestRequest("family-1")
		require.NoError(t, store.CreateAccessTokenSession(ctx, "at-sig-1", req))
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig-1", "at-sig-1", req))

		require.NoError(t, store.RotateRefreshToken(ctx, "family-1", "rt-sig-1"))

		_, err := store.GetRefreshTokenSession(ctx, "rt-sig-1", nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
		_, err = store.GetAccessTokenSession(ctx, "at-sig-1", nil)
		require.ErrorIs(t, err, fosite.ErrNotFound)
		assert.Empty(t, store.AccessTokenRequestIDs["family-1"])
	})

	t.Run("should fail when the token belongs to another family", func(t *testing.T) {
		store := NewMemoryStore()
		req := rotateTestRequest("family-1")
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig-1", "", req))

		err := store.RotateRefreshToken(ctx, "another-family", "rt-sig-1")
		require.ErrorIs(t, err, fosite.ErrNotFound)

		// the token of the other family is left untouched
		_, err = store.GetRefreshTokenSession(ctx, "rt-sig-1", nil)
		require.NoError(t, err)
	})

	t.Run("should fail when the presented generation was already rotated", func(t *testing.T) {
		store := NewMemoryStore()
		req := rotateTestRequest("family-1")
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig-1", "", req))
		require.NoError(t, store.RotateRefreshToken(ctx, "family-1", "rt-sig-1"))

		// a new generation was issued in the meantime
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig-2", "", req))

		// rotating the same (old) generation again must fail ...
		err := store.RotateRefreshToken(ctx, "family-1", "rt-sig-1")
		require.ErrorIs(t, err, fosite.ErrInactiveToken)

		// ... and must not touch the current generation, keeping exactly one
		// valid generation in the family
		_, err = store.GetRefreshTokenSession(ctx, "rt-sig-2", nil)
		require.NoError(t, err)
		_, err = store.GetRefreshTokenSession(ctx, "rt-sig-1", nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
	})

	t.Run("should rotate the presented generation even if the request ID mapping was lost", func(t *testing.T) {
		store := NewMemoryStore()
		req := rotateTestRequest("family-1")
		require.NoError(t, store.CreateRefreshTokenSession(ctx, "rt-sig-1", "", req))

		// simulate a restart after which only the token itself, but not the
		// request ID to signature mapping, was recovered
		delete(store.RefreshTokenRequestIDs, "family-1")

		require.NoError(t, store.RotateRefreshToken(ctx, "family-1", "rt-sig-1"))

		_, err := store.GetRefreshTokenSession(ctx, "rt-sig-1", nil)
		require.ErrorIs(t, err, fosite.ErrInactiveToken)
	})
}
