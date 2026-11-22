// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable_test

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
	"github.com/ory/fosite/handler/verifiable"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
)

type vcNonceManager struct{}

func (vcNonceManager) NewNonce(_ context.Context, accessToken string, _ time.Time) (string, error) {
	return "nonce-" + accessToken, nil
}

func (vcNonceManager) IsNonceValid(_ context.Context, accessToken, nonce string) error {
	if nonce != "nonce-"+accessToken {
		return fosite.ErrInactiveToken
	}
	return nil
}

func vcConfig() *fosite.Config {
	return &fosite.Config{
		GlobalSecret:                        []byte("verifiable-revocation-test-secret-0123456789"),
		AccessTokenLifespan:                 time.Hour,
		RefreshTokenLifespan:                time.Hour,
		AuthorizeCodeLifespan:               time.Minute,
		AccessTokenIssuer:                   "https://issuer.example.test",
		ScopeStrategy:                       fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:            fosite.DefaultAudienceMatchingStrategy,
		VerifiableCredentialsNonceLifespan: time.Minute,
	}
}

func vcFosite(store *storage.MemoryStore) (*fosite.Fosite, *oauth2.HMACSHAStrategy) {
	config := vcConfig()
	strategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)
	return provider.(*fosite.Fosite), strategy
}

func vcHTTPRequest(token string) *http.Request {
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	request := &http.Request{
		Method:   http.MethodPost,
		Header:   http.Header{},
		PostForm: form,
		Form:     form,
	}
	request.SetBasicAuth("my-client", "foobar")
	return request
}

func vcRestartStore(source *storage.MemoryStore) *storage.MemoryStore {
	clone := storage.NewMemoryStore()
	for key, value := range source.Clients {
		clone.Clients[key] = value
	}
	for key, value := range source.AccessTokens {
		clone.AccessTokens[key] = value
	}
	for key, value := range source.AccessTokenRequestIDs {
		clone.AccessTokenRequestIDs[key] = value
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
	for key, value := range source.TokenRevocations {
		clone.TokenRevocations[key] = value
	}
	for key, value := range source.RevokedTokenSignatures {
		clone.RevokedTokenSignatures[key] = value
	}
	clone.TokenRevocationGeneration = source.TokenRevocationGeneration
	return clone
}

func TestRevokedAccessTokenStaysInactiveForVerifiableCredentialConsumer(t *testing.T) {
	ctx := context.Background()
	store := storage.NewExampleStore()
	provider, strategy := vcFosite(store)

	request := fosite.NewRequest()
	request.SetID("vc-family")
	request.Client = &fosite.DefaultClient{ID: "my-client"}
	request.Session = &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.AccessToken: time.Now().UTC().Add(time.Hour).Round(time.Second),
		},
		Subject: "peter",
	}
	token, signature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, signature, request))

	// The verifiable credentials handler still issues a nonce for an active
	// access token. This guards the existing OpenID4VCI behavior.
	nonceHandler := &verifiable.Handler{
		Config:       vcConfig(),
		NonceManager: vcNonceManager{},
	}
	accessRequest := fosite.NewAccessRequest(&fosite.DefaultSession{})
	accessRequest.GrantedScope = fosite.Arguments{"openid", "userinfo_credential_draft_00"}
	accessResponse := fosite.NewAccessResponse()
	accessResponse.SetAccessToken(token)
	require.NoError(t, nonceHandler.PopulateTokenEndpointResponse(ctx, accessRequest, accessResponse))
	assert.NotEmpty(t, accessResponse.GetExtra("c_nonce_draft_00"))

	responder, report, err := provider.NewIntrospectionRequestWithReport(ctx, vcHTTPRequest(token), &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, responder.IsActive())
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Equal(t, "my-client", report.ClientID)
	assert.Contains(t, report.Source, "CoreValidator")

	revocationReport, err := provider.NewRevocationRequestWithReport(ctx, vcHTTPRequest(token))
	require.NoError(t, err)
	assert.True(t, revocationReport.Revoked)
	assert.Equal(t, fosite.TokenDigest(token), revocationReport.TokenDigest)
	assert.Equal(t, "my-client", revocationReport.ClientID)
	assert.Greater(t, revocationReport.RevocationGeneration, uint64(0))

	restartedStore := vcRestartStore(store)
	restarted, _ := vcFosite(restartedStore)
	responder, report, err = restarted.NewIntrospectionRequestWithReport(ctx, vcHTTPRequest(token), &fosite.DefaultSession{})
	require.Error(t, err)
	assert.False(t, responder.IsActive(), "the credential consumer must not accept a revoked token after a restart")
	assert.False(t, report.Active)
	assert.Equal(t, fosite.TokenDigest(token), report.TokenDigest)
	assert.Equal(t, "my-client", report.ClientID)
	assert.Greater(t, report.RevocationGeneration, uint64(0))
	assert.Contains(t, report.Source, "CoreValidator")
}
