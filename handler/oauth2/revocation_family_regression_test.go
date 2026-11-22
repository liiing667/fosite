// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

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
	"github.com/ory/fosite/storage"
)

func uid33147RevocationFamilyRequest(id string, client *fosite.DefaultClient) *fosite.Request {
	return &fosite.Request{
		ID:             id,
		Client:         client,
		GrantedScope:   fosite.Arguments{"offline"},
		RequestedScope: fosite.Arguments{"offline"},
		Session: &fosite.DefaultSession{
			Subject: "subject",
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().UTC().Add(time.Hour),
				fosite.RefreshToken: time.Now().UTC().Add(time.Hour),
			},
		},
		RequestedAt: time.Now().UTC(),
	}
}

func uid33147RevocationFamilyHandler(store TokenRevocationStorage) *TokenRevocationHandler {
	return &TokenRevocationHandler{
		TokenRevocationStorage: store,
		RefreshTokenStrategy:   hmacshaStrategy,
		AccessTokenStrategy:    hmacshaStrategy,
	}
}

func uid33147RefreshFamilyHandler(store TokenRevocationStorage) *RefreshTokenGrantHandler {
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

func uid33147RefreshFamilyAccessRequest(id, clientID, refreshToken string) *fosite.AccessRequest {
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.ID = id
	request.Client = &fosite.DefaultClient{
		ID:         clientID,
		GrantTypes: fosite.Arguments{"refresh_token"},
		Scopes:     fosite.Arguments{"offline"},
	}
	request.GrantTypes = fosite.Arguments{"refresh_token"}
	request.Form = url.Values{"refresh_token": {refreshToken}}
	return request
}

func TestUID33147RevocationFamilyAccessTokenRevokesRefreshChain(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	request := uid33147RevocationFamilyRequest("family-access", client)

	accessToken, accessSignature, err := hmacshaStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, accessSignature, request))
	refreshToken, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

	validator := &CoreValidator{
		CoreStrategy: hmacshaStrategy,
		CoreStorage:  store,
		Config: &fosite.Config{
			ScopeStrategy: fosite.HierarchicScopeStrategy,
		},
	}
	_, err = validator.IntrospectToken(ctx, accessToken, fosite.AccessToken, fosite.NewAccessRequest(&fosite.DefaultSession{}), nil)
	require.NoError(t, err)

	report, err := uid33147RevocationFamilyHandler(store).RevokeTokenWithReport(ctx, accessToken, fosite.AccessToken, client)
	require.NoError(t, err)
	assert.True(t, report.Revoked)
	assert.Equal(t, "family-access", report.RequestFamily)
	assert.Equal(t, fosite.AccessToken, report.TokenUse)

	_, err = store.GetAccessTokenSession(ctx, accessSignature, nil)
	require.Error(t, err)
	_, err = store.GetRefreshTokenSession(ctx, refreshSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	_, err = validator.IntrospectToken(ctx, accessToken, fosite.AccessToken, fosite.NewAccessRequest(&fosite.DefaultSession{}), nil)
	require.ErrorIs(t, err, fosite.ErrRequestUnauthorized)

	refresh := uid33147RefreshFamilyAccessRequest("family-access", "client", refreshToken)
	err = uid33147RefreshFamilyHandler(store).HandleTokenEndpointRequest(ctx, refresh)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())

	// A create for the revoked family must not be able to resurrect it.
	require.ErrorIs(t, store.CreateRefreshTokenSession(ctx, "new-refresh", "new-access", request), fosite.ErrInactiveToken)
	require.ErrorIs(t, store.CreateAccessTokenSession(ctx, "new-access", request), fosite.ErrInactiveToken)
}

func TestUID33147RevocationFamilyOldAccessTokenRevokesCurrentGeneration(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	request := uid33147RevocationFamilyRequest("family-old-access", client)

	oldAccess, oldAccessSignature, err := hmacshaStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, oldAccessSignature, request))
	oldRefresh, oldRefreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, oldRefreshSignature, oldAccessSignature, request))

	// Rotate to a new generation first. The old access token session is gone,
	// but revoking it must still revoke the current refresh generation.
	refreshHandler := uid33147RefreshFamilyHandler(store)
	refreshRequest := uid33147RefreshFamilyAccessRequest("family-old-access", "client", oldRefresh)
	response := fosite.NewAccessResponse()
	require.NoError(t, refreshHandler.PopulateTokenEndpointResponse(ctx, refreshRequest, response))
	currentRefresh, ok := response.ToMap()["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, currentRefresh)
	currentRefreshSignature := hmacshaStrategy.RefreshTokenSignature(ctx, currentRefresh)
	_, err = store.GetRefreshTokenSession(ctx, currentRefreshSignature, nil)
	require.NoError(t, err)

	require.NoError(t, uid33147RevocationFamilyHandler(store).RevokeToken(ctx, oldAccess, fosite.AccessToken, client))
	_, err = store.GetRefreshTokenSession(ctx, currentRefreshSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	require.True(t, uid33147MustFamilyRevoked(t, store, "family-old-access"))
}

func uid33147MustFamilyRevoked(t *testing.T, store *storage.MemoryStore, requestID string) bool {
	t.Helper()
	revoked, err := store.IsTokenFamilyRevoked(context.Background(), requestID)
	require.NoError(t, err)
	return revoked
}

type uid33147RevocationAccessFailureStore struct {
	TokenRevocationStorage
}

func (s *uid33147RevocationAccessFailureStore) RevokeAccessToken(context.Context, string) error {
	return errors.New("access token storage unavailable")
}

func TestUID33147RevocationFamilyPartialFailureLeavesCompleteTombstone(t *testing.T) {
	ctx := context.Background()
	memoryStore := storage.NewMemoryStore()
	store := &uid33147RevocationAccessFailureStore{TokenRevocationStorage: memoryStore}
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	request := uid33147RevocationFamilyRequest("family-partial", client)

	accessToken, accessSignature, err := hmacshaStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, memoryStore.CreateAccessTokenSession(ctx, accessSignature, request))
	refreshToken, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, memoryStore.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

	err = uid33147RevocationFamilyHandler(store).RevokeToken(ctx, accessToken, fosite.AccessToken, client)
	require.EqualError(t, err, fosite.ErrTemporarilyUnavailable.Error())

	revoked, err := memoryStore.IsTokenFamilyRevoked(ctx, "family-partial")
	require.NoError(t, err)
	assert.True(t, revoked)

	_, err = memoryStore.GetAccessTokenSession(ctx, accessSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	_, err = memoryStore.GetRefreshTokenSession(ctx, refreshSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)

	err = uid33147RefreshFamilyHandler(store).HandleTokenEndpointRequest(ctx, uid33147RefreshFamilyAccessRequest("family-partial", "client", refreshToken))
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())
}

func uid33147CloneRevocationFamilyLegacyMaps(source *storage.MemoryStore) *storage.MemoryStore {
	clone := storage.NewMemoryStore()
	for key, value := range source.Clients {
		clone.Clients[key] = value
	}
	for key, value := range source.AccessTokens {
		clone.AccessTokens[key] = value
	}
	for key, value := range source.RefreshTokens {
		clone.RefreshTokens[key] = value
	}
	for key, value := range source.AccessTokenRequestIDs {
		clone.AccessTokenRequestIDs[key] = value
	}
	for key, value := range source.RefreshTokenRequestIDs {
		clone.RefreshTokenRequestIDs[key] = value
	}
	return clone
}

func TestUID33147RevocationFamilyTombstoneSurvivesLegacyMapRestart(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	request := uid33147RevocationFamilyRequest("family-restart", client)

	accessToken, accessSignature, err := hmacshaStrategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, accessSignature, request))
	refreshToken, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

	require.NoError(t, uid33147RevocationFamilyHandler(store).RevokeToken(ctx, accessToken, fosite.AccessToken, client))

	// Simulate a restart implementation that only knows the original map
	// fields. The empty request-ID markers are part of those maps and keep the
	// family fail-closed.
	restarted := uid33147CloneRevocationFamilyLegacyMaps(store)
	revoked, err := restarted.IsTokenFamilyRevoked(ctx, "family-restart")
	require.NoError(t, err)
	assert.True(t, revoked)
	require.ErrorIs(t, restarted.CreateRefreshTokenSession(ctx, "restart-refresh", "restart-access", request), fosite.ErrInactiveToken)
	require.ErrorIs(t, restarted.CreateAccessTokenSession(ctx, "restart-access", request), fosite.ErrInactiveToken)

	err = uid33147RefreshFamilyHandler(restarted).HandleTokenEndpointRequest(ctx, uid33147RefreshFamilyAccessRequest("family-restart", "client", refreshToken))
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())
}

func TestUID33147RevocationFamilyConcurrentRefreshCannotOutliveRevocation(t *testing.T) {
	ctx := context.Background()
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	revocation := uid33147RevocationFamilyHandler(nil)

	for i := 0; i < 20; i++ {
		store := storage.NewMemoryStore()
		request := uid33147RevocationFamilyRequest("family-concurrent", client)

		accessToken, accessSignature, err := hmacshaStrategy.GenerateAccessToken(ctx, request)
		require.NoError(t, err)
		require.NoError(t, store.CreateAccessTokenSession(ctx, accessSignature, request))
		refreshToken, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
		require.NoError(t, err)
		require.NoError(t, store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

		revocation.TokenRevocationStorage = store
		refreshHandler := uid33147RefreshFamilyHandler(store)
		refreshRequest := uid33147RefreshFamilyAccessRequest("family-concurrent", "client", refreshToken)
		response := fosite.NewAccessResponse()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = revocation.RevokeToken(ctx, accessToken, fosite.AccessToken, client)
		}()
		go func() {
			defer wg.Done()
			_ = refreshHandler.PopulateTokenEndpointResponse(ctx, refreshRequest, response)
		}()
		wg.Wait()

		revoked, err := store.IsTokenFamilyRevoked(ctx, "family-concurrent")
		require.NoError(t, err)
		require.True(t, revoked)
		_, err = store.GetRefreshTokenSession(ctx, refreshSignature, nil)
		require.Error(t, err)

		if token := response.GetAccessToken(); token != "" {
			signature := hmacshaStrategy.AccessTokenSignature(ctx, token)
			_, err = store.GetAccessTokenSession(ctx, signature, nil)
			require.Error(t, err, "an access token created concurrently with revocation must not stay active")
		}
	}
}

type uid33147RevocationCreateRefreshFailureStore struct {
	TokenRevocationStorage
}

func (s *uid33147RevocationCreateRefreshFailureStore) CreateRefreshTokenSession(context.Context, string, string, fosite.Requester) error {
	return errors.New("refresh token storage unavailable")
}

func TestUID33147RefreshFamilyPartialFailureDoesNotExposeNewAccessToken(t *testing.T) {
	ctx := context.Background()
	memoryStore := storage.NewMemoryStore()
	store := &uid33147RevocationCreateRefreshFailureStore{TokenRevocationStorage: memoryStore}
	client := &fosite.DefaultClient{ID: "client", GrantTypes: fosite.Arguments{"refresh_token"}, Scopes: fosite.Arguments{"offline"}}
	request := uid33147RevocationFamilyRequest("family-refresh-partial", client)

	refreshToken, refreshSignature, err := hmacshaStrategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, memoryStore.CreateRefreshTokenSession(ctx, refreshSignature, "", request))

	accessRequest := uid33147RefreshFamilyAccessRequest("family-refresh-partial", "client", refreshToken)
	response := fosite.NewAccessResponse()
	err = uid33147RefreshFamilyHandler(store).PopulateTokenEndpointResponse(ctx, accessRequest, response)
	require.Error(t, err)
	assert.Empty(t, response.GetAccessToken())

	revoked, err := memoryStore.IsTokenFamilyRevoked(ctx, "family-refresh-partial")
	require.NoError(t, err)
	assert.True(t, revoked, "a failed second storage step must leave a complete family tombstone")
}
