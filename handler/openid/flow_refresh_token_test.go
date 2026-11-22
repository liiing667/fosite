// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/token/jwt"
)

func TestOpenIDConnectRefreshHandler_HandleTokenEndpointRequest(t *testing.T) {
	h := &OpenIDConnectRefreshHandler{Config: &fosite.Config{}}
	for _, c := range []struct {
		areq        *fosite.AccessRequest
		expectedErr error
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: fosite.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: fosite.ErrUnknownRequest,
		},
		{
			description: "should not pass because client may not execute this grant type",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client:       &fosite.DefaultClient{},
				},
			},
			expectedErr: fosite.ErrUnauthorizedClient,
		},
		{
			description: "should pass",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client: &fosite.DefaultClient{
						GrantTypes: []string{"refresh_token"},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{},
				},
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			err := h.HandleTokenEndpointRequest(context.Background(), c.areq)
			if c.expectedErr != nil {
				require.EqualError(t, err, c.expectedErr.Error(), "%v", err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestOpenIDConnectRefreshHandler_PopulateTokenEndpointResponse(t *testing.T) {
	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: &fosite.Config{
			MinParameterEntropy: fosite.MinParameterEntropy,
		},
	}

	h := &OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		Config: &fosite.Config{},
	}
	for _, c := range []struct {
		areq        *fosite.AccessRequest
		expectedErr error
		check       func(t *testing.T, aresp *fosite.AccessResponse)
		description string
	}{
		{
			description: "should not pass because grant_type is wrong",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"foo"},
			},
			expectedErr: fosite.ErrUnknownRequest,
		},
		{
			description: "should not pass because grant_type is right but scope is missing",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"something"},
				},
			},
			expectedErr: fosite.ErrUnknownRequest,
		},
		// Disabled because this is already handled at the authorize_request_handler
		//{
		//	description: "should not pass because client may not ask for id_token",
		//	areq: &fosite.AccessRequest{
		//		GrantTypes: []string{"refresh_token"},
		//		Request: fosite.Request{
		//			GrantedScope: []string{"openid"},
		//			Client: &fosite.DefaultClient{
		//				GrantTypes: []string{"refresh_token"},
		//			},
		//		},
		//	},
		//	expectedErr: fosite.ErrUnknownRequest,
		//},
		{
			description: "should pass",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client: &fosite.DefaultClient{
						GrantTypes: []string{"refresh_token"},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims: &jwt.IDTokenClaims{
							Subject: "foo",
						},
					},
				},
			},
			check: func(t *testing.T, aresp *fosite.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(time.Hour).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should pass",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client: &fosite.DefaultClientWithCustomTokenLifespans{
						DefaultClient: &fosite.DefaultClient{
							GrantTypes: []string{"refresh_token"},
							//ResponseTypes: []string{"id_token"},
						},
						TokenLifespans: &internal.TestLifespans,
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims: &jwt.IDTokenClaims{
							Subject: "foo",
						},
					},
				},
			},
			check: func(t *testing.T, aresp *fosite.AccessResponse) {
				assert.NotEmpty(t, aresp.GetExtra("id_token"))
				idToken, _ := aresp.GetExtra("id_token").(string)
				decodedIdToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
					return key.PublicKey, nil
				})
				require.NoError(t, err)
				claims := decodedIdToken.Claims
				assert.NotEmpty(t, claims["at_hash"])
				idTokenExp := internal.ExtractJwtExpClaim(t, idToken)
				require.NotEmpty(t, idTokenExp)
				internal.RequireEqualTime(t, time.Now().Add(*internal.TestLifespans.RefreshTokenGrantIDTokenLifespan).UTC(), *idTokenExp, time.Minute)
			},
		},
		{
			description: "should fail because missing subject claim",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client: &fosite.DefaultClient{
						GrantTypes: []string{"refresh_token"},
						//ResponseTypes: []string{"id_token"},
					},
					Session: &DefaultSession{
						Subject: "foo",
						Claims:  &jwt.IDTokenClaims{},
					},
				},
			},
			expectedErr: fosite.ErrServerError,
		},
		{
			description: "should fail because missing session",
			areq: &fosite.AccessRequest{
				GrantTypes: []string{"refresh_token"},
				Request: fosite.Request{
					GrantedScope: []string{"openid"},
					Client: &fosite.DefaultClient{
						GrantTypes: []string{"refresh_token"},
					},
				},
			},
			expectedErr: fosite.ErrServerError,
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := fosite.NewAccessResponse()
			err := h.PopulateTokenEndpointResponse(context.Background(), c.areq, aresp)
			if c.expectedErr != nil {
				require.EqualError(t, err, c.expectedErr.Error(), "%v", err)
			} else {
				require.NoError(t, err)
			}

			if c.check != nil {
				c.check(t, aresp)
			}
		})
	}
}

func newRefreshTestHandler() *OpenIDConnectRefreshHandler {
	var j = &DefaultStrategy{
		Signer: &jwt.DefaultSigner{
			GetPrivateKey: func(ctx context.Context) (interface{}, error) {
				return key, nil
			},
		},
		Config: &fosite.Config{
			MinParameterEntropy: fosite.MinParameterEntropy,
		},
	}

	return &OpenIDConnectRefreshHandler{
		IDTokenHandleHelper: &IDTokenHandleHelper{
			IDTokenStrategy: j,
		},
		Config: &fosite.Config{},
	}
}

func newRefreshTestRequest(claims *jwt.IDTokenClaims) *fosite.AccessRequest {
	return &fosite.AccessRequest{
		GrantTypes: []string{"refresh_token"},
		Request: fosite.Request{
			GrantedScope: []string{"openid"},
			Client: &fosite.DefaultClient{
				GrantTypes: []string{"refresh_token"},
			},
			Form: url.Values{
				"grant_type": {"refresh_token"},
			},
			Session: &DefaultSession{
				Subject: claims.Subject,
				Claims:  claims,
				Headers: &jwt.Headers{},
			},
		},
	}
}

func parseIDTokenClaims(t *testing.T, raw string) jwt.MapClaims {
	t.Helper()
	parsed, err := jwt.Parse(raw, func(token *jwt.Token) (interface{}, error) {
		return key.PublicKey, nil
	})
	require.NoError(t, err)
	return parsed.Claims
}

// TestOpenIDConnectRefreshHandler_GenerationKeepsIdentityClaims ensures that a
// refresh keeps the nonce and auth_time of the authorizing session while still
// producing a fresh at_hash for the new access token.
func TestOpenIDConnectRefreshHandler_GenerationKeepsIdentityClaims(t *testing.T) {
	h := newRefreshTestHandler()

	authTime := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	request := newRefreshTestRequest(&jwt.IDTokenClaims{
		Subject:  "peter",
		Nonce:    "the-original-session-nonce",
		AuthTime: authTime,
		// Values from a previous generation must be wiped and recomputed.
		JTI:             "stale-jti",
		AccessTokenHash: "stale-at-hash",
		CodeHash:        "stale-c-hash",
		ExpiresAt:       time.Now().Add(-time.Minute),
	})

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), request))

	// The working session keeps pointing at the immutable generation snapshot:
	// stale per-generation values are gone, while the identity claims remain
	// untouched.
	generation, sess := refreshGenerationFromSession(request.GetSession().(Session))
	require.NotNil(t, generation)
	assert.NotEmpty(t, generation.jti)
	workingClaims := generation.claims
	assert.Equal(t, "the-original-session-nonce", workingClaims.Nonce)
	assert.True(t, workingClaims.AuthTime.Equal(authTime))
	assert.Empty(t, workingClaims.JTI)
	assert.Empty(t, workingClaims.AccessTokenHash)
	assert.Empty(t, workingClaims.CodeHash)
	assert.True(t, workingClaims.ExpiresAt.IsZero())
	// The wrapped original session must still expose the same identity claims.
	assert.Equal(t, "the-original-session-nonce", sess.IDTokenClaims().Nonce)

	response := fosite.NewAccessResponse()
	response.SetAccessToken("the-new-access-token")
	require.NoError(t, h.PopulateTokenEndpointResponse(context.Background(), request, response))

	claims := parseIDTokenClaims(t, response.GetExtra("id_token").(string))
	assert.Equal(t, "peter", claims["sub"])
	assert.Equal(t, "the-original-session-nonce", claims["nonce"])
	assert.Equal(t, float64(authTime.Unix()), claims["auth_time"])
	assert.NotEmpty(t, claims["at_hash"])
	assert.NotEmpty(t, claims["jti"])
	assert.NotEqual(t, "stale-jti", claims["jti"])
	assert.NotEqual(t, "stale-at-hash", claims["at_hash"])
	_, hasCHash := claims["c_hash"]
	assert.False(t, hasCHash)
}

// TestOpenIDConnectRefreshHandler_NoNonceStaysOmitted documents the
// compatibility boundary for legitimate older sessions that never carried a
// nonce: the refreshed ID token must not invent one and must remain valid.
func TestOpenIDConnectRefreshHandler_NoNonceStaysOmitted(t *testing.T) {
	h := newRefreshTestHandler()

	request := newRefreshTestRequest(&jwt.IDTokenClaims{
		Subject:  "peter",
		AuthTime: time.Now().UTC().Add(-time.Hour).Truncate(time.Second),
	})
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), request))

	response := fosite.NewAccessResponse()
	response.SetAccessToken("access-token")
	require.NoError(t, h.PopulateTokenEndpointResponse(context.Background(), request, response))

	claims := parseIDTokenClaims(t, response.GetExtra("id_token").(string))
	_, hasNonce := claims["nonce"]
	assert.False(t, hasNonce)
	assert.NotEmpty(t, claims["at_hash"])
	assert.NotEmpty(t, claims["auth_time"])
}

// TestOpenIDConnectRefreshHandler_RetryReusesGeneration proves that a lost
// response followed by a retry can not leave two verifiable ID tokens behind:
// every rebuild of the same generation yields the same jti and identity
// claims, only the time bound is recomputed.
func TestOpenIDConnectRefreshHandler_RetryReusesGeneration(t *testing.T) {
	h := newRefreshTestHandler()

	authTime := time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Second)
	request := newRefreshTestRequest(&jwt.IDTokenClaims{
		Subject:  "peter",
		Nonce:    "stable-session-nonce",
		AuthTime: authTime,
	})
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), request))

	first := fosite.NewAccessResponse()
	first.SetAccessToken("first-access-token")
	require.NoError(t, h.PopulateTokenEndpointResponse(context.Background(), request, first))

	// Simulate a lost response: the client retries with the same request, so
	// PopulateTokenEndpointResponse runs again against the same generation.
	second := fosite.NewAccessResponse()
	second.SetAccessToken("second-access-token")
	require.NoError(t, h.PopulateTokenEndpointResponse(context.Background(), request, second))

	firstClaims := parseIDTokenClaims(t, first.GetExtra("id_token").(string))
	secondClaims := parseIDTokenClaims(t, second.GetExtra("id_token").(string))

	assert.Equal(t, firstClaims["jti"], secondClaims["jti"], "retries must not mint a second ID token identity")
	assert.Equal(t, firstClaims["nonce"], secondClaims["nonce"])
	assert.Equal(t, firstClaims["auth_time"], secondClaims["auth_time"])
	assert.NotEqual(t, firstClaims["at_hash"], secondClaims["at_hash"], "each response still binds its own access token")

	// Re-building the response must not have mutated the persisted identity
	// snapshot, so a later hydration observes a clean generation.
	generation, sess := refreshGenerationFromSession(request.GetSession().(Session))
	require.NotNil(t, generation)
	claims := generation.claims
	assert.Equal(t, "stable-session-nonce", claims.Nonce)
	assert.True(t, claims.AuthTime.Equal(authTime))
	assert.Empty(t, claims.AccessTokenHash)
	assert.Equal(t, "stable-session-nonce", sess.IDTokenClaims().Nonce)
}

// TestOpenIDConnectRefreshHandler_ConcurrentResponsesShareOneGeneration
// reproduces the out-of-order completion of concurrent responses: many
// goroutines build ID tokens from the same hydrated request. All resulting
// tokens must belong to the same generation (identical jti/nonce/auth_time)
// instead of mixing claims across generations.
func TestOpenIDConnectRefreshHandler_ConcurrentResponsesShareOneGeneration(t *testing.T) {
	h := newRefreshTestHandler()

	authTime := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Second)
	request := newRefreshTestRequest(&jwt.IDTokenClaims{
		Subject:  "peter",
		Nonce:    "concurrent-session-nonce",
		AuthTime: authTime,
	})
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(), request))

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]jwt.MapClaims, goroutines)
	errs := make(chan error, goroutines)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			// Signing and claim assembly must be race-free; report failures
			// through the channel instead of failing the test from a
			// non-test goroutine.
			response := fosite.NewAccessResponse()
			response.SetAccessToken("access-token-" + strconv.Itoa(i))
			if err := h.PopulateTokenEndpointResponse(context.Background(), request, response); err != nil {
				errs <- err
				return
			}
			rawIDToken, ok := response.GetExtra("id_token").(string)
			if !ok {
				errs <- errors.New("id_token was not set on the response")
				return
			}
			parsed, err := jwt.Parse(rawIDToken, func(token *jwt.Token) (interface{}, error) {
				return key.PublicKey, nil
			})
			if err != nil {
				errs <- err
				return
			}
			results[i] = parsed.Claims
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	reference := results[0]
	for _, claims := range results[1:] {
		assert.Equal(t, reference["jti"], claims["jti"])
		assert.Equal(t, reference["nonce"], claims["nonce"])
		assert.Equal(t, reference["auth_time"], claims["auth_time"])
		assert.Equal(t, reference["sub"], claims["sub"])
		assert.NotEmpty(t, claims["at_hash"])
	}

	// The session snapshot must still be pristine after the concurrent storm.
	generation, sess := refreshGenerationFromSession(request.GetSession().(Session))
	require.NotNil(t, generation)
	assert.Equal(t, "concurrent-session-nonce", generation.claims.Nonce)
	assert.True(t, generation.claims.AuthTime.Equal(authTime))
	assert.Empty(t, generation.claims.AccessTokenHash)
	assert.Equal(t, "concurrent-session-nonce", sess.IDTokenClaims().Nonce)
}
