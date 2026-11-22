// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
	"github.com/ory/fosite/token/jwt"
)

func revocationGenerationConfig() *fosite.Config {
	return &fosite.Config{
		GlobalSecret:             []byte("revocation-generation-test-secret-0123456789"),
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour,
		AuthorizeCodeLifespan:    time.Minute,
		AccessTokenIssuer:        "https://issuer.example.test",
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}
}

func revocationGenerationRequest(requestID, clientID string) *fosite.Request {
	request := fosite.NewRequest()
	request.SetID(requestID)
	request.Client = &fosite.DefaultClient{ID: clientID}
	request.Session = &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken:  time.Now().UTC().Add(time.Hour).Round(time.Second),
			fosite.RefreshToken: time.Now().UTC().Add(time.Hour).Round(time.Second),
		},
		Subject: "peter",
	}
	return request
}

func revocationGenerationJWTRequest(requestID, clientID string) *fosite.Request {
	request := revocationGenerationRequest(requestID, clientID)
	request.Session = &oauth2.JWTSession{
		JWTClaims: &jwt.JWTClaims{Subject: "peter"},
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken: time.Now().UTC().Add(time.Hour).Round(time.Second),
		},
	}
	return request
}

func revocationGenerationCloneStore(source *storage.MemoryStore) *storage.MemoryStore {
	clone := storage.NewMemoryStore()
	for key, value := range source.Clients {
		clone.Clients[key] = value
	}
	for key, value := range source.Users {
		clone.Users[key] = value
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
	for key, value := range source.AccessTokenGenerations {
		clone.AccessTokenGenerations[key] = value
	}
	for key, value := range source.AccessTokenGenerationCounters {
		clone.AccessTokenGenerationCounters[key] = value
	}
	for key, value := range source.AccessTokenRevocationGenerations {
		clone.AccessTokenRevocationGenerations[key] = value
	}
	for key, value := range source.RefreshTokenGenerations {
		clone.RefreshTokenGenerations[key] = value
	}
	for key, value := range source.RefreshTokenGenerationCounters {
		clone.RefreshTokenGenerationCounters[key] = value
	}
	for key, value := range source.RefreshTokenRevocationGenerations {
		clone.RefreshTokenRevocationGenerations[key] = value
	}
	for key, value := range source.TokenRevocations {
		clone.TokenRevocations[key] = value
	}
	for key, value := range source.RevokedTokenSignatures {
		clone.RevokedTokenSignatures[key] = value
	}
	clone.TokenRevocationGeneration = source.TokenRevocationGeneration
	return clone
}

func revocationGenerationHTTPRequest(token, tokenTypeHint string) *http.Request {
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	request := &http.Request{
		Method:   http.MethodPost,
		Header:   http.Header{},
		PostForm: form,
		Form:     form,
	}
	request.SetBasicAuth("my-client", "foobar")
	return request
}

func revocationGenerationHMACFosite() (*fosite.Fosite, *storage.MemoryStore, *oauth2.HMACSHAStrategy) {
	config := revocationGenerationConfig()
	strategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
	store := storage.NewExampleStore()
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)
	return provider.(*fosite.Fosite), store, strategy
}

func revocationGenerationJWTStrategy(config *fosite.Config, key interface{}) *oauth2.DefaultJWTStrategy {
	return &oauth2.DefaultJWTStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(context.Context) (interface{}, error) {
				return key, nil
			},
		},
		HMACSHAStrategy: oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config),
		Config:          config,
	}
}

func TestRevocationGenerationStoreConsistency(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	first := revocationGenerationRequest("access-family", "my-client")
	second := revocationGenerationRequest("access-family", "my-client")
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-signature-1", first))
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-signature-2", second))

	_, err := store.GetAccessTokenSession(ctx, "access-signature-1", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	revoked, err := store.IsTokenSignatureRevoked(ctx, "access-signature-1")
	require.NoError(t, err)
	assert.True(t, revoked, "the superseded access token generation must stay revoked")

	require.NoError(t, store.RevokeAccessToken(ctx, "access-family"))
	_, err = store.GetAccessTokenSession(ctx, "access-signature-2", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	revoked, err = store.IsTokenSignatureRevoked(ctx, "access-signature-2")
	require.NoError(t, err)
	assert.True(t, revoked)

	third := revocationGenerationRequest("access-family", "my-client")
	require.NoError(t, store.CreateAccessTokenSession(ctx, "access-signature-3", third))
	_, err = store.GetAccessTokenSession(ctx, "access-signature-3", nil)
	require.NoError(t, err, "a token created after the revocation must be a new active generation")
	revoked, err = store.IsTokenSignatureRevoked(ctx, "access-signature-3")
	require.NoError(t, err)
	assert.False(t, revoked)

	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-signature-1", "access-signature-1", first))
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-signature-2", "access-signature-2", second))
	_, err = store.GetRefreshTokenSession(ctx, "refresh-signature-1", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)

	require.NoError(t, store.RevokeRefreshToken(ctx, "access-family"))
	_, err = store.GetRefreshTokenSession(ctx, "refresh-signature-2", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, "refresh-signature-3", "access-signature-3", third))
	_, err = store.GetRefreshTokenSession(ctx, "refresh-signature-3", nil)
	require.NoError(t, err, "a refresh token created after the revocation must be a new active generation")

	restarted := revocationGenerationCloneStore(store)
	_, err = restarted.GetAccessTokenSession(ctx, "access-signature-3", nil)
	require.NoError(t, err)
	_, err = restarted.GetAccessTokenSession(ctx, "access-signature-2", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	_, err = restarted.GetRefreshTokenSession(ctx, "refresh-signature-3", nil)
	require.NoError(t, err)
	_, err = restarted.GetRefreshTokenSession(ctx, "refresh-signature-2", nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
	revoked, err = restarted.IsTokenSignatureRevoked(ctx, "access-signature-2")
	require.NoError(t, err)
	assert.True(t, revoked, "signature revocation evidence must survive a restart")
}

func TestIntrospectionRevocationReportSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	f, store, strategy := revocationGenerationHMACFosite()
	request := revocationGenerationRequest("introspection-family", "my-client")
	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	responder, report, err := f.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, responder.IsActive())
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Equal(t, "my-client", report.ClientID)
	assert.Contains(t, report.Source, "CoreValidator")
	assert.True(t, report.Active)

	revocationReport, err := f.NewRevocationRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"))
	require.NoError(t, err)
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenStatusStageRevoked, revocationReport.Stage)
	assert.Equal(t, fosite.TokenDigest(token), revocationReport.TokenDigest)
	assert.Equal(t, "my-client", revocationReport.ClientID)
	assert.Contains(t, revocationReport.Source, "TokenRevocationHandler")
	assert.NotEmpty(t, revocationReport.StatusSource)
	assert.Empty(t, revocationReport.FailureLocation)
	assert.Greater(t, revocationReport.RevocationGeneration, uint64(0))

	responder, report, err = f.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Equal(t, "my-client", report.ClientID)
	assert.Contains(t, report.Source, "CoreValidator")
	assert.NotEmpty(t, report.StatusSource)
	assert.Greater(t, report.RevocationGeneration, uint64(0))
	assert.NotEmpty(t, report.Stage)
	assert.Equal(t, fosite.TokenStatusStageIntrospection, report.FailureLocation)
	assert.NotEmpty(t, report.Error)

	restartedStore := revocationGenerationCloneStore(store)
	restartedConfig := revocationGenerationConfig()
	restartedStrategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: restartedConfig}, restartedConfig)
	restarted := compose.Compose(
		restartedConfig,
		restartedStore,
		restartedStrategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	).(*fosite.Fosite)

	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Greater(t, report.RevocationGeneration, uint64(0))
	assert.Contains(t, report.Source, "CoreValidator")

	nextRequest := revocationGenerationRequest("introspection-family", "my-client")
	nextToken, nextSignature, err := restartedStrategy.GenerateAccessToken(ctx, nextRequest)
	require.NoError(t, err)
	require.NoError(t, restartedStore.CreateAccessTokenSession(ctx, nextSignature, nextRequest))
	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(nextToken, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	assert.True(t, responder.IsActive())
	assert.True(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(nextToken), report.TokenDigest)
}

func TestStatelessJWTRevocationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	config := revocationGenerationConfig()
	key := gen.MustRSAKey()
	strategy := revocationGenerationJWTStrategy(config, key)
	store := storage.NewExampleStore()
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)

	request := revocationGenerationJWTRequest("jwt-family", "my-client")
	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	responder, report, err := provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	assert.True(t, responder.IsActive())
	assert.Equal(t, "my-client", report.ClientID)
	assert.Contains(t, report.Source, "StatelessJWTValidator")

	revocationReport, err := provider.NewRevocationRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"))
	require.NoError(t, err)
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenDigest(token), revocationReport.TokenDigest)

	responder, report, err = provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Contains(t, report.Source, "StatelessJWTValidator")

	restartedStore := revocationGenerationCloneStore(store)
	restartedConfig := revocationGenerationConfig()
	restartedStrategy := revocationGenerationJWTStrategy(restartedConfig, key)
	restarted := compose.Compose(
		restartedConfig,
		restartedStore,
		restartedStrategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)

	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive(), "a revoked stateless JWT must stay inactive after a restart")
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)

	nextRequest := revocationGenerationJWTRequest("jwt-family", "my-client")
	nextToken, nextSignature, err := restartedStrategy.GenerateAccessToken(ctx, nextRequest)
	require.NoError(t, err)
	require.NoError(t, restartedStore.CreateAccessTokenSession(ctx, nextSignature, nextRequest))
	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(nextToken, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	assert.True(t, responder.IsActive(), "a new JWT generation after revocation must be active")
	assert.True(t, report.Active)
}

func TestRefreshTokenRevocationInvalidatesStatelessAccessJWT(t *testing.T) {
	ctx := context.Background()
	config := revocationGenerationConfig()
	key := gen.MustRSAKey()
	strategy := revocationGenerationJWTStrategy(config, key)
	store := storage.NewExampleStore()
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)

	request := revocationGenerationJWTRequest("jwt-family-refresh", "my-client")
	accessToken, accessSignature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, accessSignature, request))
	refreshToken, refreshSignature, err := strategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

	responder, _, err := provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(accessToken, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, responder.IsActive())

	revocationReport, err := provider.NewRevocationRequestWithReport(ctx, revocationGenerationHTTPRequest(refreshToken, "refresh_token"))
	require.NoError(t, err)
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenDigest(refreshToken), revocationReport.TokenDigest)

	responder, report, err := provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(accessToken, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive(), "revoking the refresh token must invalidate its stateless access JWT sibling")
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(accessToken), report.TokenDigest)

	restartedStore := revocationGenerationCloneStore(store)
	restartedConfig := revocationGenerationConfig()
	restartedStrategy := revocationGenerationJWTStrategy(restartedConfig, key)
	restarted := compose.Compose(
		restartedConfig,
		restartedStore,
		restartedStrategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)
	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(accessToken, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, report.Active)
}

func TestStatelessJWTRevocationWithoutStoredSession(t *testing.T) {
	ctx := context.Background()
	config := revocationGenerationConfig()
	key := gen.MustRSAKey()
	strategy := revocationGenerationJWTStrategy(config, key)
	store := storage.NewExampleStore()
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)

	request := revocationGenerationJWTRequest("jwt-family-stateless", "my-client")
	token, _, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)

	responder, _, err := provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, responder.IsActive())

	revocationReport, err := provider.NewRevocationRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"))
	require.NoError(t, err)
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenDigest(token), revocationReport.TokenDigest)
	assert.Greater(t, revocationReport.Generation, uint64(0))

	responder, report, err := provider.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive(), "a stateless JWT with no stored session must still be revocable")
	assert.False(t, report.Active)

	restartedStore := revocationGenerationCloneStore(store)
	restartedConfig := revocationGenerationConfig()
	restartedStrategy := revocationGenerationJWTStrategy(restartedConfig, key)
	restarted := compose.Compose(
		restartedConfig,
		restartedStore,
		restartedStrategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2StatelessJWTIntrospectionFactory,
	).(*fosite.Fosite)
	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest(token, "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, report.Active)
}

func TestRevocationAndIntrospectionReportFailureLocation(t *testing.T) {
	ctx := context.Background()
	f, _, _ := revocationGenerationHMACFosite()

	_, report, err := f.NewIntrospectionRequestWithReport(ctx, revocationGenerationHTTPRequest("no-such-token", "access_token"), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, report.Active)
	assert.NotEmpty(t, report.TokenDigest)
	assert.Equal(t, "my-client", report.ClientID)
	assert.NotEmpty(t, report.Stage)
	assert.NotEmpty(t, report.Error)

	revocationReport, err := f.NewRevocationRequestWithReport(ctx, revocationGenerationHTTPRequest("no-such-token", "access_token"))
	require.NoError(t, err, "revoking an unknown token is idempotent and must keep returning success")
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenStatusStageRevoked, revocationReport.Stage)
	assert.NotEmpty(t, revocationReport.TokenDigest)
	assert.Equal(t, "my-client", revocationReport.ClientID)
	assert.Contains(t, revocationReport.Source, "TokenRevocationHandler")

	badAuthRequest := revocationGenerationHTTPRequest("some-token", "access_token")
	badAuthRequest.SetBasicAuth("my-client", "wrong-secret")
	revocationReport, err = f.NewRevocationRequestWithReport(ctx, badAuthRequest)
	require.Error(t, err)
	assert.Equal(t, fosite.TokenStatusStageAuthentication, revocationReport.Stage)
	assert.Equal(t, fosite.TokenStatusStageAuthentication, revocationReport.FailureLocation)
	assert.Equal(t, "my-client", revocationReport.ClientID)
	assert.NotEmpty(t, revocationReport.Error)
}
