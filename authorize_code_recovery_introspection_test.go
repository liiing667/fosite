// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestUID33146IntrospectionMetadata(t *testing.T) {
	ctx := context.Background()
	config := &fosite.Config{
		GlobalSecret:             []byte("authorize-code-recovery-test-secret-0123456789"),
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour,
		AuthorizeCodeLifespan:    time.Minute,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
		RefreshTokenScopes:       []string{},
	}
	store := storage.NewExampleStore()
	strategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
	).(*fosite.Fosite)

	authorizeURL := "/authorize?" + url.Values{
		"client_id":     {"my-client"},
		"redirect_uri":  {"http://localhost:3846/callback"},
		"response_type": {"code"},
		"scope":         {"fosite"},
		"state":         {"0123456789abcdef"},
	}.Encode()
	authorizeHTTPRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	authorizeRequest, err := provider.NewAuthorizeRequest(ctx, authorizeHTTPRequest)
	require.NoError(t, err)
	require.NotEmpty(t, fosite.RequesterRecoveryGeneration(authorizeRequest))
	require.NotEmpty(t, fosite.RequesterClientRevision(authorizeRequest))

	session := &fosite.DefaultSession{Subject: "peter"}
	authorizeResponse, err := provider.NewAuthorizeResponse(ctx, authorizeRequest, session)
	require.NoError(t, err)
	require.NotEmpty(t, authorizeResponse.GetCode())

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {authorizeResponse.GetCode()},
		"redirect_uri": {"http://localhost:3846/callback"},
	}
	tokenHTTPRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenHTTPRequest.SetBasicAuth("my-client", "foobar")
	accessRequest, err := provider.NewAccessRequest(ctx, tokenHTTPRequest, &fosite.DefaultSession{})
	require.NoError(t, err)
	accessResponse, err := provider.NewAccessResponse(ctx, accessRequest)
	require.NoError(t, err)
	require.NotEmpty(t, accessResponse.GetAccessToken())

	// Replaying the consumed code must not create a second token generation,
	// and it must not revoke the single legitimate generation.
	replayHTTPRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	replayHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayHTTPRequest.SetBasicAuth("my-client", "foobar")
	_, err = provider.NewAccessRequest(ctx, replayHTTPRequest, &fosite.DefaultSession{})
	require.Error(t, err)
	assert.Len(t, store.AccessTokens, 1)

	introspectionForm := url.Values{
		"token":           {accessResponse.GetAccessToken()},
		"token_type_hint": {"access_token"},
	}
	introspectionHTTPRequest := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(introspectionForm.Encode()))
	introspectionHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectionHTTPRequest.SetBasicAuth("my-client", "foobar")
	introspectionResponse, err := provider.NewIntrospectionRequest(ctx, introspectionHTTPRequest, &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, introspectionResponse.IsActive())

	insight, ok := introspectionResponse.(*fosite.IntrospectionResponse)
	require.True(t, ok)
	assert.NotEmpty(t, insight.ClientRevision)
	assert.Equal(t, insight.ClientRevision, insight.ClientVersion)
	assert.NotZero(t, insight.ClientGeneration)
	assert.NotZero(t, insight.RecoveryGeneration)
	assert.Equal(t, insight.RecoveryGeneration, insight.Generation)
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, insight.AuthorizationCodeStatus)
	assert.Equal(t, insight.AuthorizationCodeStatus, insight.CodeStatus)
	assert.Empty(t, insight.RejectionStage)

	recorder := httptest.NewRecorder()
	provider.WriteIntrospectionResponse(ctx, recorder, introspectionResponse)
	require.Equal(t, http.StatusOK, recorder.Code)

	var body map[string]interface{}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, true, body["active"])
	assert.Equal(t, "my-client", body["client_id"])
	assert.NotEmpty(t, body["client_version"])
	assert.NotEmpty(t, body["client_revision"])
	assert.NotZero(t, body["client_generation"])
	assert.NotZero(t, body["recovery_generation"])
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, body["authorization_code_status"])
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, body["code_status"])

	refreshToken, ok := accessResponse.ToMap()["refresh_token"].(string)
	require.True(t, ok)
	refreshIntrospectionForm := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	refreshHTTPRequest := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(refreshIntrospectionForm.Encode()))
	refreshHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshHTTPRequest.SetBasicAuth("my-client", "foobar")
	refreshResponse, err := provider.NewIntrospectionRequest(ctx, refreshHTTPRequest, &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, refreshResponse.IsActive())
	refreshInsight, ok := refreshResponse.(*fosite.IntrospectionResponse)
	require.True(t, ok)
	assert.Equal(t, insight.ClientRevision, refreshInsight.ClientRevision)
	assert.Equal(t, insight.RecoveryGeneration, refreshInsight.RecoveryGeneration)
	assert.Equal(t, insight.AuthorizationCodeStatus, refreshInsight.AuthorizationCodeStatus)
}

func TestUID33146PublicClientPKCECompatibility(t *testing.T) {
	ctx := context.Background()
	config := &fosite.Config{
		GlobalSecret:             []byte("public-client-pkce-recovery-test-secret-0123456789"),
		AccessTokenLifespan:      time.Hour,
		RefreshTokenLifespan:     time.Hour,
		AuthorizeCodeLifespan:    time.Minute,
		ScopeStrategy:            fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy: fosite.DefaultAudienceMatchingStrategy,
	}
	store := storage.NewExampleStore()
	store.Clients["public-client"] = &fosite.DefaultClient{
		ID:            "public-client",
		Public:        true,
		RedirectURIs:  []string{"http://localhost:3846/callback"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
		Scopes:        []string{"openid", "fosite"},
	}
	strategy := oauth2.NewHMACSHAStrategy(&hmac.HMACStrategy{Config: config}, config)
	provider := compose.Compose(
		config,
		store,
		strategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory,
		compose.OAuth2TokenIntrospectionFactory,
	).(*fosite.Fosite)

	verifier := "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	authorizeURL := "/authorize?" + url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"http://localhost:3846/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid fosite"},
		"state":                 {"0123456789abcdef"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	authorizeHTTPRequest := httptest.NewRequest(http.MethodGet, authorizeURL, nil)
	authorizeRequest, err := provider.NewAuthorizeRequest(ctx, authorizeHTTPRequest)
	require.NoError(t, err)
	authorizeResponse, err := provider.NewAuthorizeResponse(ctx, authorizeRequest, &fosite.DefaultSession{Subject: "peter"})
	require.NoError(t, err)
	require.NotEmpty(t, authorizeResponse.GetCode())

	// A failed PKCE proof must not consume the code or the PKCE binding.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"public-client"},
		"code":          {authorizeResponse.GetCode()},
		"redirect_uri":  {"http://localhost:3846/callback"},
		"code_verifier": {verifier + "x"},
	}
	tokenHTTPRequest := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = provider.NewAccessRequest(ctx, tokenHTTPRequest, &fosite.DefaultSession{})
	require.Error(t, err)

	tokenForm.Set("code_verifier", verifier)
	tokenHTTPRequest = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	accessRequest, err := provider.NewAccessRequest(ctx, tokenHTTPRequest, &fosite.DefaultSession{})
	require.NoError(t, err)
	accessResponse, err := provider.NewAccessResponse(ctx, accessRequest)
	require.NoError(t, err)
	require.NotEmpty(t, accessResponse.GetAccessToken())

	signature := strategy.AuthorizeCodeSignature(ctx, authorizeResponse.GetCode())
	_, err = store.GetPKCERequestSession(ctx, signature, nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)

	introspectionForm := url.Values{"token": {accessResponse.GetAccessToken()}}
	introspectionHTTPRequest := httptest.NewRequest(http.MethodPost, "/introspect", strings.NewReader(introspectionForm.Encode()))
	introspectionHTTPRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectionHTTPRequest.SetBasicAuth("my-client", "foobar")
	introspectionResponse, err := provider.NewIntrospectionRequest(ctx, introspectionHTTPRequest, &fosite.DefaultSession{})
	require.NoError(t, err)
	require.True(t, introspectionResponse.IsActive())
	assert.Equal(t, "public-client", introspectionResponse.GetAccessRequester().GetClient().GetID())
	assert.Equal(t, fosite.AuthorizeCodeStatusConsumed, fosite.RequesterAuthorizeCodeStatus(introspectionResponse.GetAccessRequester()))
}
