// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// refreshRotationTestHandler returns a RefreshTokenGrantHandler mirroring the
// setup of the other refresh flow tests.
func refreshRotationTestHandler(store TokenRevocationStorage) *RefreshTokenGrantHandler {
	return &RefreshTokenGrantHandler{
		TokenRevocationStorage: store,
		RefreshTokenStrategy:   hmacshaStrategy,
		AccessTokenStrategy:    hmacshaStrategy,
		Config: &fosite.Config{
			AccessTokenLifespan:      time.Hour,
			RefreshTokenLifespan:     time.Hour,
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		},
	}
}

func refreshRotationTestRequest(id, clientID, refreshToken string) *fosite.AccessRequest {
	areq := fosite.NewAccessRequest(&fosite.DefaultSession{})
	areq.ID = id
	areq.Client = &fosite.DefaultClient{
		ID:         clientID,
		Scopes:     []string{"foo", "offline"},
		GrantTypes: fosite.Arguments{"refresh_token"},
	}
	areq.GrantTypes = fosite.Arguments{"refresh_token"}
	areq.Form = url.Values{}
	areq.Form.Add("refresh_token", refreshToken)
	return areq
}

func refreshRotationTestSession(id, clientID string, scopes fosite.Arguments) *fosite.Request {
	return &fosite.Request{
		ID:           id,
		Client:       &fosite.DefaultClient{ID: clientID},
		GrantedScope: scopes,
		Session:      &fosite.DefaultSession{Subject: "sub"},
		RequestedAt:  time.Now().UTC(),
	}
}

// Two requests presenting the same refresh token generation (e.g. because of a
// concurrent retry) must not both succeed: only the first one rotates the
// token, the second one fails and the family keeps exactly one valid
// generation.
func TestRefreshFlow_PopulateTokenEndpointResponse_ConcurrentRotationKeepsOneGeneration(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := refreshRotationTestHandler(store)

	token, signature, err := hmacshaStrategy.GenerateRefreshToken(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", refreshRotationTestSession("family-1", "foo", fosite.Arguments{"foo"})))

	// the first request rotates generation 1 into generation 2
	areq1 := refreshRotationTestRequest("family-1", "foo", token)
	aresp1 := fosite.NewAccessResponse()
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, areq1, aresp1))
	generation2, ok := aresp1.ToMap()["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, generation2)

	// a second request presenting the same (now rotated) generation must fail
	areq2 := refreshRotationTestRequest("family-1", "foo", token)
	aresp2 := fosite.NewAccessResponse()
	err = handler.PopulateTokenEndpointResponse(ctx, areq2, aresp2)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidRequest.Error())

	// generation 2 is the only valid generation of the family
	_, err = store.GetRefreshTokenSession(ctx, hmacshaStrategy.RefreshTokenSignature(ctx, generation2), nil)
	require.NoError(t, err)
	_, err = store.GetRefreshTokenSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

// A refresh token family must keep exactly one valid generation even if the
// request ID to signature mapping was lost (e.g. after a restart): the
// rotation is pinned to the presented token.
func TestRefreshFlow_PopulateTokenEndpointResponse_RotationSurvivesLostMapping(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := refreshRotationTestHandler(store)

	token, signature, err := hmacshaStrategy.GenerateRefreshToken(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature, "", refreshRotationTestSession("family-1", "foo", fosite.Arguments{"foo"})))

	// simulate a restart after which the request ID to signature mapping was lost
	delete(store.RefreshTokenRequestIDs, "family-1")

	areq := refreshRotationTestRequest("family-1", "foo", token)
	aresp := fosite.NewAccessResponse()
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, areq, aresp))

	// the presented generation was rotated out and can not be used again
	_, err = store.GetRefreshTokenSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}

// failingCreateRefreshTokenSessionStorage simulates a storage error when the
// new token generation is persisted, after the rotation already happened.
type failingCreateRefreshTokenSessionStorage struct {
	TokenRevocationStorage
	err error
}

func (s *failingCreateRefreshTokenSessionStorage) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, req fosite.Requester) error {
	return s.err
}

// If persisting the new generation fails, the old (already rotated) generation
// must not be usable for another refresh: the next request presenting it is
// treated as token reuse and the whole family is revoked.
func TestRefreshFlow_StorageErrorLeavesNoValidGeneration(t *testing.T) {
	ctx := context.Background()
	memoryStore := storage.NewMemoryStore()
	store := &failingCreateRefreshTokenSessionStorage{
		TokenRevocationStorage: memoryStore,
		err:                    errors.New("storage is unavailable"),
	}
	handler := refreshRotationTestHandler(store)

	token, signature, err := hmacshaStrategy.GenerateRefreshToken(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, memoryStore.CreateRefreshTokenSession(ctx, signature, "", refreshRotationTestSession("family-1", "foo", fosite.Arguments{"foo"})))

	// the rotation succeeds, but persisting the new generation fails
	areq := refreshRotationTestRequest("family-1", "foo", token)
	aresp := fosite.NewAccessResponse()
	err = handler.PopulateTokenEndpointResponse(ctx, areq, aresp)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrServerError.Error())

	// the old generation was rotated out and does not refresh again
	_, err = memoryStore.GetRefreshTokenSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)

	// a retry with the old generation is handled as token reuse and revokes the
	// family instead of extending access
	retry := refreshRotationTestRequest("family-1", "foo", token)
	err = handler.HandleTokenEndpointRequest(ctx, retry)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())
}

// Reusing a rotated refresh token revokes the whole family: the current
// generation must not survive the reuse of an old generation.
func TestRefreshFlow_HandleTokenEndpointRequest_ReuseRevokesFamily(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := refreshRotationTestHandler(store)

	token1, signature1, err := hmacshaStrategy.GenerateRefreshToken(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, signature1, "", refreshRotationTestSession("family-1", "foo", fosite.Arguments{"offline"})))

	// the legitimate client rotates generation 1 into generation 2
	areq := refreshRotationTestRequest("family-1", "foo", token1)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, areq))
	aresp := fosite.NewAccessResponse()
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, areq, aresp))
	token2, ok := aresp.ToMap()["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, token2)

	// an old (stolen) generation is presented - this is detected as reuse
	reuse := refreshRotationTestRequest("family-1", "foo", token1)
	err = handler.HandleTokenEndpointRequest(ctx, reuse)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())

	// and the whole family, including the current generation, is revoked
	_, err = store.GetRefreshTokenSession(ctx, hmacshaStrategy.RefreshTokenSignature(ctx, token2), nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	_, err = store.GetRefreshTokenSession(ctx, signature1, nil)
	require.Error(t, err)
}
