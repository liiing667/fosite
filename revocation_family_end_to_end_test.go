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
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/hmac"
)

func uid33147RevocationHTTPRequest(token string) *http.Request {
	form := url.Values{"token": {token}}
	request := &http.Request{
		Method:   http.MethodPost,
		Header:   http.Header{},
		PostForm: form,
	}
	request.SetBasicAuth("my-client", "foobar")
	return request
}

func TestUID33147RevocationFamilyEndToEnd(t *testing.T) {
	ctx := context.Background()
	config := &fosite.Config{
		GlobalSecret:             []byte("revocation-family-test-secret-0123456789"),
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour,
		AccessTokenIssuer:        "https://issuer.example.test",
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}
	store := storage.NewExampleStore()
	strategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2TokenRevocationFactory,
		compose.OAuth2TokenIntrospectionFactory,
	).(*fosite.Fosite)

	client, err := store.GetClient(ctx, "my-client")
	require.NoError(t, err)
	request := &fosite.Request{
		ID:             "family-end-to-end",
		Client:         client,
		GrantedScope:   fosite.Arguments{"offline"},
		RequestedScope: fosite.Arguments{"offline"},
		RequestedAt:    time.Now().UTC(),
		Session: &fosite.DefaultSession{
			Subject: "subject",
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken:  time.Now().UTC().Add(time.Hour),
				fosite.RefreshToken: time.Now().UTC().Add(time.Hour),
			},
		},
	}

	accessToken, accessSignature, err := strategy.GenerateAccessToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateAccessTokenSession(ctx, accessSignature, request))
	refreshToken, refreshSignature, err := strategy.GenerateRefreshToken(ctx, request)
	require.NoError(t, err)
	require.NoError(t, store.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, request))

	activeResponder, activeReport, err := provider.NewIntrospectionRequestWithReport(
		ctx,
		uid33147RevocationHTTPRequest(accessToken),
		&fosite.DefaultSession{},
	)
	require.NoError(t, err)
	assert.True(t, activeResponder.IsActive())
	assert.True(t, activeReport.Active)
	assert.Equal(t, "family-end-to-end", activeReport.RequestFamily)
	assert.Equal(t, fosite.AccessToken, activeReport.TokenUse)

	report, err := provider.NewRevocationRequestWithReport(ctx, uid33147RevocationHTTPRequest(accessToken))
	require.NoError(t, err)
	assert.True(t, report.Revoked)
	assert.Equal(t, fosite.TokenStatusStageRevoked, report.Stage)
	assert.Equal(t, "family-end-to-end", report.RequestFamily)
	assert.Equal(t, fosite.TokenDigest(accessToken), report.TokenDigest)

	responder, introspectionReport, err := provider.NewIntrospectionRequestWithReport(
		ctx,
		uid33147RevocationHTTPRequest(accessToken),
		&fosite.DefaultSession{},
	)
	require.Error(t, err)
	assert.False(t, responder.IsActive())
	assert.False(t, introspectionReport.Active)
	assert.Equal(t, fosite.TokenDigest(accessToken), introspectionReport.TokenDigest)
	assert.Equal(t, "my-client", introspectionReport.ClientID)
	assert.Equal(t, "family-end-to-end", introspectionReport.RequestFamily)
	assert.Equal(t, fosite.AccessToken, introspectionReport.TokenUse)
	assert.True(t, introspectionReport.Revoked)
	assert.Equal(t, fosite.TokenStatusStageIntrospection, introspectionReport.FailureLocation)

	refreshHandler := &oauth2.RefreshTokenGrantHandler{
		AccessTokenStrategy:    strategy,
		RefreshTokenStrategy:   strategy,
		TokenRevocationStorage: store,
		Config:                 config,
	}
	refreshRequest := fosite.NewAccessRequest(&fosite.DefaultSession{})
	refreshRequest.ID = "family-end-to-end"
	refreshRequest.Client = client
	refreshRequest.GrantTypes = fosite.Arguments{"refresh_token"}
	refreshRequest.Form = url.Values{"refresh_token": {refreshToken}}
	err = refreshHandler.HandleTokenEndpointRequest(ctx, refreshRequest)
	require.Error(t, err)
	assert.EqualError(t, err, fosite.ErrInvalidGrant.Error())

	// A retry of the revocation must stay idempotent and must not recreate the
	// old family.
	_, err = provider.NewRevocationRequestWithReport(ctx, uid33147RevocationHTTPRequest(accessToken))
	require.NoError(t, err)
	_, err = store.GetRefreshTokenSession(ctx, refreshSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)

	unknownReport, err := provider.NewRevocationRequestWithReport(ctx, uid33147RevocationHTTPRequest("unknown-token"))
	require.NoError(t, err)
	assert.True(t, unknownReport.Revoked)
	assert.Equal(t, fosite.TokenStatusStageRevoked, unknownReport.Stage)

	badAuth := uid33147RevocationHTTPRequest("some-token")
	badAuth.SetBasicAuth("my-client", "wrong-secret")
	authReport, err := provider.NewRevocationRequestWithReport(ctx, badAuth)
	require.Error(t, err)
	assert.Equal(t, fosite.TokenStatusStageAuthentication, authReport.Stage)
	assert.Equal(t, fosite.TokenStatusStageAuthentication, authReport.FailureLocation)
	assert.Equal(t, "my-client", authReport.ClientID)
}
