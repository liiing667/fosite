// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

func uid33146NewAuthorizeCodeRecoveryHandler(store *storage.MemoryStore) *AuthorizeExplicitGrantHandler {
	return &AuthorizeExplicitGrantHandler{
		CoreStorage:            store,
		TokenRevocationStorage: store,
		AuthorizeCodeStrategy:  hmacshaStrategy,
		AccessTokenStrategy:    hmacshaStrategy,
		RefreshTokenStrategy:   hmacshaStrategy,
		Config: &fosite.Config{
			ScopeStrategy:            fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
			AuthorizeCodeLifespan:    time.Minute,
			AccessTokenLifespan:      time.Minute,
			RefreshTokenLifespan:     time.Hour,
			RefreshTokenScopes:       []string{"offline"},
		},
	}
}

func uid33146IssueAuthorizeCodeForClient(t *testing.T, ctx context.Context, handler *AuthorizeExplicitGrantHandler, client fosite.Client) (string, string) {
	t.Helper()

	areq := fosite.NewAuthorizeRequest()
	areq.Client = client
	areq.Session = &fosite.DefaultSession{}
	areq.Form.Set("redirect_uri", "https://client.example/callback")
	areq.SetRequestedScopes(fosite.Arguments{"openid", "offline"})
	areq.GrantScope("openid")
	areq.GrantScope("offline")

	aresp := fosite.NewAuthorizeResponse()
	require.NoError(t, handler.IssueAuthorizeCode(ctx, areq, aresp))
	require.NotEmpty(t, aresp.GetCode())
	require.NotEmpty(t, areq.GetRecoveryGeneration())
	require.NotEmpty(t, areq.GetClientRevision())

	return aresp.GetCode(), hmacshaStrategy.AuthorizeCodeSignature(ctx, aresp.GetCode())
}

func uid33146NewAuthorizeCodeTokenRequest(code string, client fosite.Client) *fosite.AccessRequest {
	r := fosite.NewAccessRequest(&fosite.DefaultSession{})
	r.GrantTypes = fosite.Arguments{"authorization_code"}
	r.Client = client
	r.Form.Set("code", code)
	r.Form.Set("redirect_uri", "https://client.example/callback")
	return r
}

func TestUID33146_ClientRotationConsumesExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)

	clientV1 := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret-v1"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "offline"},
		Audience:      []string{"api"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, clientV1)

	stored := store.AuthorizeCodes[signature]
	require.True(t, stored.Active)
	assert.Equal(t, fosite.AuthorizeCodeStatusActive, stored.Status)
	assert.NotZero(t, stored.Generation)
	assert.Equal(t, fosite.ClientRevision(clientV1), stored.ClientRevision)

	// Rotate the secret. The old credential remains valid for authentication
	// during the rotation window, but only one exchange may commit.
	clientV2 := &fosite.DefaultClient{
		ID:             "client",
		Secret:         []byte("secret-v2"),
		RotatedSecrets: [][]byte{[]byte("secret-v1")},
		RedirectURIs:   []string{"https://client.example/callback"},
		GrantTypes:     []string{"authorization_code", "refresh_token"},
		ResponseTypes:  []string{"code"},
		Scopes:         []string{"openid", "offline"},
		Audience:       []string{"api"},
	}
	require.NotEqual(t, fosite.ClientRevision(clientV1), fosite.ClientRevision(clientV2))

	oldRequest := uid33146NewAuthorizeCodeTokenRequest(code, clientV1)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, oldRequest))

	newRequest := uid33146NewAuthorizeCodeTokenRequest(code, clientV2)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, newRequest))

	response := fosite.NewAccessResponse()
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, newRequest, response))
	require.NotEmpty(t, response.GetAccessToken())

	// The old client version cannot start a second token family.
	require.ErrorIs(t, handler.PopulateTokenEndpointResponse(ctx, oldRequest, fosite.NewAccessResponse()), fosite.ErrInvalidGrant)
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, clientV1)), fosite.ErrInvalidGrant)

	// The code has exactly one tombstone and exactly one token generation.
	stored = store.AuthorizeCodes[signature]
	assert.False(t, stored.Active)
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, stored.Status)
	assert.NotZero(t, stored.ConsumedAt)
	assert.Len(t, store.AccessTokens, 1)

	accessSignature := hmacshaStrategy.AccessTokenSignature(ctx, response.GetAccessToken())
	accessRequest, err := store.GetAccessTokenSession(ctx, accessSignature, nil)
	require.NoError(t, err)
	assert.Equal(t, fosite.ClientRevision(clientV2), accessRequest.(*fosite.Request).GetClientRevision())
	assert.Equal(t, stored.Generation, accessRequest.(*fosite.Request).GetRecoveryGeneration())
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, accessRequest.(*fosite.Request).GetAuthorizeCodeStatus())
}

func TestUID33146_ConcurrentExchangeSucceedsOnce(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	const attempts = 12
	var wg sync.WaitGroup
	var succeeded atomic.Int64
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			request := uid33146NewAuthorizeCodeTokenRequest(code, client)
			if err := handler.HandleTokenEndpointRequest(ctx, request); err != nil {
				return
			}
			if err := handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()); err != nil {
				return
			}
			succeeded.Add(1)
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 1, succeeded.Load())
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, store.AuthorizeCodes[signature].Status)
	assert.Len(t, store.AccessTokens, 1)
}

type uid33146FailingAccessTokenStore struct {
	*storage.MemoryStore
	failCreateAccessToken bool
}

func (s *uid33146FailingAccessTokenStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	if s.failCreateAccessToken {
		return errors.New("injected access token storage failure")
	}
	return s.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

type uid33146FailingRefreshTokenStore struct {
	*storage.MemoryStore
	failCreateRefreshToken bool
}

func (s *uid33146FailingRefreshTokenStore) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request fosite.Requester) error {
	if s.failCreateRefreshToken {
		return errors.New("injected refresh token storage failure")
	}
	return s.MemoryStore.CreateRefreshTokenSession(ctx, signature, accessSignature, request)
}

func TestUID33146_FailedTokenCreationKeepsConsumptionTombstone(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemoryStore()
	store := &uid33146FailingAccessTokenStore{MemoryStore: base, failCreateAccessToken: true}
	handler := uid33146NewAuthorizeCodeRecoveryHandler(base)
	handler.CoreStorage = store

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	request := uid33146NewAuthorizeCodeTokenRequest(code, client)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
	require.Error(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()))

	// The claim is a tombstone even though token creation failed: a retry from
	// the same or an old client version cannot mint a new token.
	stored := base.AuthorizeCodes[signature]
	assert.False(t, stored.Active)
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, stored.Status)
	_, err := handler.CoreStorage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, client)), fosite.ErrInvalidGrant)
	require.ErrorIs(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()), fosite.ErrInvalidGrant)
}

func TestUID33146_FailedRefreshTokenCreationLeavesNoPartialToken(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemoryStore()
	store := &uid33146FailingRefreshTokenStore{MemoryStore: base, failCreateRefreshToken: true}
	handler := uid33146NewAuthorizeCodeRecoveryHandler(base)
	handler.CoreStorage = store

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "offline"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	request := uid33146NewAuthorizeCodeTokenRequest(code, client)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
	require.Error(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()))

	assert.Empty(t, base.AccessTokens)
	assert.Empty(t, base.RefreshTokens)
	assert.False(t, base.AuthorizeCodes[signature].Active)
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, base.AuthorizeCodes[signature].Status)
}

type uid33146FailingClaimStore struct {
	*storage.MemoryStore
	failConsume bool
}

func (s *uid33146FailingClaimStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	if s.failConsume {
		return errors.New("injected authorize code claim failure")
	}
	return s.MemoryStore.InvalidateAuthorizeCodeSession(ctx, code)
}

func TestUID33146_FailedClaimLeavesNoRedeemableCode(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemoryStore()
	store := &uid33146FailingClaimStore{MemoryStore: base, failConsume: true}
	handler := uid33146NewAuthorizeCodeRecoveryHandler(base)
	handler.CoreStorage = store

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	request := uid33146NewAuthorizeCodeTokenRequest(code, client)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
	require.Error(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()))

	stored := base.AuthorizeCodes[signature]
	assert.False(t, stored.Active)
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, stored.Status)
	assert.Equal(t, fosite.RecoveryStageTokenCreation, stored.RejectionStage)

	// Even after the injected storage failure disappears, the old code cannot
	// be redeemed again.
	store.failConsume = false
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, client)), fosite.ErrInvalidGrant)
	_, err := handler.CoreStorage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
}

func TestUID33146_HardRotationRejectsOldCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)

	clientV1 := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret-v1"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, clientV1)

	// No rotated secret: the new registration is not a successor of the old
	// one, so the outstanding code cannot be redeemed by either version.
	clientV2 := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret-v2"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, clientV2)), fosite.ErrInvalidGrant)

	// A rejected version must not consume the code for the frozen version.
	_, err := handler.CoreStorage.GetAuthorizeCodeSession(ctx, signature, nil)
	require.NoError(t, err)
	require.True(t, uid33146BaseActive(store, signature))
}

func TestUID33146_InPlaceRotationKeepsFrozenSecret(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret-v1"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	// Simulate a store that mutates its client object instead of replacing it.
	client.Secret = []byte("secret-v2")
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, client)), fosite.ErrInvalidGrant)
	require.True(t, uid33146BaseActive(store, signature))
}

func TestUID33146_RedirectBindingSurvivesCustomWhitelist(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)
	handler.Config.(*fosite.Config).SanitationWhiteList = []string{"code_challenge"}

	client := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, client)

	stored := store.AuthorizeCodes[signature]
	assert.Empty(t, stored.GetRequestForm().Get("redirect_uri"), "the custom whitelist drops the form value")
	assert.Equal(t, "https://client.example/callback", fosite.RequesterAuthorizationRedirectURI(stored.Requester))

	wrongRedirect := uid33146NewAuthorizeCodeTokenRequest(code, client)
	wrongRedirect.Form.Set("redirect_uri", "https://attacker.example/callback")
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, wrongRedirect), fosite.ErrInvalidGrant)
	require.True(t, uid33146BaseActive(store, signature), "a redirect mismatch must not consume the code")

	request := uid33146NewAuthorizeCodeTokenRequest(code, client)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()))
}

func TestUID33146_StaleClientObjectCannotRedeemAfterStoreRotation(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	handler := uid33146NewAuthorizeCodeRecoveryHandler(store)

	clientV1 := &fosite.DefaultClient{
		ID:            "client",
		Secret:        []byte("secret-v1"),
		RedirectURIs:  []string{"https://client.example/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid"},
	}
	store.Clients[clientV1.ID] = clientV1
	code, signature := uid33146IssueAuthorizeCodeForClient(t, ctx, handler, clientV1)

	clientV2 := &fosite.DefaultClient{
		ID:             "client",
		Secret:         []byte("secret-v2"),
		RotatedSecrets: [][]byte{[]byte("secret-v1")},
		RedirectURIs:   []string{"https://client.example/callback"},
		GrantTypes:     []string{"authorization_code"},
		ResponseTypes:  []string{"code"},
		Scopes:         []string{"openid"},
	}
	store.Clients[clientV2.ID] = clientV2

	// A request carrying the stale object must fail even though that object is
	// the exact revision that issued the code.
	require.ErrorIs(t, handler.HandleTokenEndpointRequest(ctx, uid33146NewAuthorizeCodeTokenRequest(code, clientV1)), fosite.ErrInvalidGrant)
	require.True(t, uid33146BaseActive(store, signature))

	// The currently registered successor can redeem it exactly once.
	request := uid33146NewAuthorizeCodeTokenRequest(code, clientV2)
	require.NoError(t, handler.HandleTokenEndpointRequest(ctx, request))
	require.NoError(t, handler.PopulateTokenEndpointResponse(ctx, request, fosite.NewAccessResponse()))
}

func TestUID33146JWTMetadataRoundTrip(t *testing.T) {
	session := &JWTSession{JWTClaims: &jwt.JWTClaims{}}
	request := fosite.NewAccessRequest(session)
	setAuthorizeCodeRecoverySessionClaims(request, "client-revision-v2", 7, 42)

	converted := AccessTokenJWTToRequest(&jwt.Token{Claims: jwt.MapClaims(session.JWTClaims.ToMap())})
	assert.Equal(t, "client-revision-v2", fosite.RequesterClientRevision(converted))
	assert.EqualValues(t, 7, fosite.RequesterClientGeneration(converted))
	assert.EqualValues(t, 42, fosite.RequesterRecoveryGeneration(converted))
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, fosite.RequesterAuthorizeCodeStatus(converted))
	assert.Equal(t, fosite.RecoveryStageAuthorizeCodeConsumed, fosite.RequesterAuthorizeCodeStage(converted))
}

func uid33146BaseActive(store *storage.MemoryStore, signature string) bool {
	code, ok := store.AuthorizeCodes[signature]
	return ok && code.Active
}
