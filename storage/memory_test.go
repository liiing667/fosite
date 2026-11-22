// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

func TestMemoryStore_Authenticate(t *testing.T) {
	type fields struct {
		Users      map[string]MemoryUserRelation
		usersMutex sync.RWMutex
	}
	type args struct {
		in0    context.Context
		name   string
		secret string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr error
	}{
		{
			name: "invalid_password",
			args: args{
				name:   "peter",
				secret: "invalid",
			},
			fields: fields{
				Users: map[string]MemoryUserRelation{
					"peter": {
						Username: "peter",
						Password: "secret",
					},
				},
			},
			// ResourceOwnerPasswordCredentialsGrantHandler expects ErrNotFound
			wantErr: fosite.ErrNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &MemoryStore{
				Users:      tt.fields.Users,
				usersMutex: tt.fields.usersMutex,
			}
			if _, err := s.Authenticate(tt.args.in0, tt.args.name, tt.args.secret); err == nil || !errors.Is(err, tt.wantErr) {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func newStoredRefreshRequest(id string) *fosite.Request {
	return &fosite.Request{
		ID:             id,
		Client:         &fosite.DefaultClient{ID: "client"},
		GrantedScope:   fosite.Arguments{"openid", "offline"},
		RequestedScope: fosite.Arguments{"openid", "offline"},
		Form:           url.Values{"grant_type": {"refresh_token"}},
		RequestedAt:    time.Now().UTC(),
		Session: &openid.DefaultSession{
			Subject: "peter",
			Claims: &jwt.IDTokenClaims{
				Subject:  "peter",
				Nonce:    "session-nonce",
				AuthTime: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
			},
			Headers: &jwt.Headers{},
		},
	}
}

// TestMemoryStore_RefreshSessionIsolation makes sure that mutating the session
// of a hydrated refresh request can not change the persisted generation. This
// is the in-memory equivalent of the serialization boundary that SQL
// storages get for free.
func TestMemoryStore_RefreshSessionIsolation(t *testing.T) {
	store := NewMemoryStore()
	original := newStoredRefreshRequest("request-id")

	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), "old-sig", "old-at-sig", original))

	hydrated, err := store.GetRefreshTokenSession(context.Background(), "old-sig", nil)
	require.NoError(t, err)

	session := hydrated.GetSession().(openid.Session)
	session.IDTokenClaims().Nonce = "mutated-nonce"
	session.IDTokenClaims().AccessTokenHash = "mutated-at-hash"

	again, err := store.GetRefreshTokenSession(context.Background(), "old-sig", nil)
	require.NoError(t, err)
	againClaims := again.GetSession().(openid.Session).IDTokenClaims()
	assert.Equal(t, "session-nonce", againClaims.Nonce)
	assert.Empty(t, againClaims.AccessTokenHash)

	// Writing a new generation must not alter the caller's request either.
	rotated := newStoredRefreshRequest("request-id")
	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), "new-sig", "new-at-sig", rotated))
	assert.Equal(t, "session-nonce", original.GetSession().(openid.Session).IDTokenClaims().Nonce)
}

// TestMemoryStore_ConcurrentRefreshRotationLeavesOneGeneration proves that two
// concurrent refreshes racing on the same refresh token can not both install a
// valid generation. Exactly one rotation succeeds; the competing request fails
// with a retryable serialization error instead of leaving two verifiable
// token pairs behind.
func TestMemoryStore_ConcurrentRefreshRotationLeavesOneGeneration(t *testing.T) {
	store := NewMemoryStore()
	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), "shared-sig", "at-sig", newStoredRefreshRequest("request-id")))

	const goroutines = 16
	var wg sync.WaitGroup
	var successes, failures, serializationFailures int
	var mu sync.Mutex

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			err := store.RotateRefreshToken(context.Background(), "request-id", "shared-sig")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, fosite.ErrSerializationFailure):
				serializationFailures++
				failures++
			default:
				failures++
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, 1, successes, "exactly one concurrent rotation must win")
	assert.Equal(t, goroutines-1, failures)
	assert.Equal(t, goroutines-1, serializationFailures)

	// The losing requests must observe an inactive token and therefore be
	// funneled into the reuse/retry path on their next attempt.
	_, err := store.GetRefreshTokenSession(context.Background(), "shared-sig", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

// TestMemoryStore_RotateUnknownRefreshTokenFails makes sure an unknown refresh
// token is still rejected with a not found error so the regular retry behavior
// stays intact.
func TestMemoryStore_RotateUnknownRefreshTokenFails(t *testing.T) {
	store := NewMemoryStore()
	err := store.RotateRefreshToken(context.Background(), "request-id", "missing-sig")
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestMemoryStore_HydrationAfterRotationReadsSameGeneration shows that the
// generation which wins a rotation is exactly what a later hydration (for
// example after a restart that loses the in-flight response) reads back. The
// client can therefore only ever recover the single committed generation.
func TestMemoryStore_HydrationAfterRotationReadsSameGeneration(t *testing.T) {
	store := NewMemoryStore()
	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), "old-sig", "old-at-sig", newStoredRefreshRequest("request-id")))

	require.NoError(t, store.RotateRefreshToken(context.Background(), "request-id", "old-sig"))

	nextGeneration := newStoredRefreshRequest("request-id")
	nextGeneration.Session.(*openid.DefaultSession).Claims.Nonce = "next-generation-nonce"
	require.NoError(t, store.CreateAccessTokenSession(context.Background(), "new-at-sig", nextGeneration))
	require.NoError(t, store.CreateRefreshTokenSession(context.Background(), "new-sig", "new-at-sig", nextGeneration))

	// Restart/retry style reads must observe the new generation, never the old
	// one, and every read returns an independent copy.
	hydrated, err := store.GetRefreshTokenSession(context.Background(), "new-sig", nil)
	require.NoError(t, err)
	hydratedClaims := hydrated.GetSession().(openid.Session).IDTokenClaims()
	assert.Equal(t, "next-generation-nonce", hydratedClaims.Nonce)

	hydratedClaims.Nonce = "tampered-nonce"
	hydratedAgain, err := store.GetRefreshTokenSession(context.Background(), "new-sig", nil)
	require.NoError(t, err)
	assert.Equal(t, "next-generation-nonce", hydratedAgain.GetSession().(openid.Session).IDTokenClaims().Nonce)

	// The rotated token must stay unusable so retrying with it can not create a
	// competing, second generation.
	_, err = store.GetRefreshTokenSession(context.Background(), "old-sig", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}
