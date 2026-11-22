// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc7523_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gomock "go.uber.org/mock/gomock"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/rfc7523"
	"github.com/ory/fosite/internal"
	"github.com/ory/fosite/storage"
)

const (
	jtiRegressionGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"
	jtiRegressionTokenURL  = "https://www.example.com/token"
	jtiRegressionIssuer    = "trusted_issuer"
	jtiRegressionSubject   = "some_ro"
	jtiRegressionKeyID     = "my_key"
)

func newJTIRegressionHandler(store rfc7523.RFC7523KeyStorage) *rfc7523.Handler {
	return &rfc7523.Handler{
		Storage: store,
		Config: &fosite.Config{
			ScopeStrategy:                        fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:             fosite.DefaultAudienceMatchingStrategy,
			TokenURL:                             jtiRegressionTokenURL,
			GrantTypeJWTBearerCanSkipClientAuth:  false,
			GrantTypeJWTBearerIDOptional:         false,
			GrantTypeJWTBearerIssuedDateOptional: false,
			GrantTypeJWTBearerMaxDuration:        time.Hour * 24 * 30,
		},
		HandleHelper: &oauth2.HandleHelper{
			Config: &fosite.Config{
				AccessTokenLifespan: time.Hour,
			},
		},
	}
}

func jtiRegressionClaims(id string) jwt.Claims {
	return jwt.Claims{
		Issuer:   jtiRegressionIssuer,
		Subject:  jtiRegressionSubject,
		Audience: jwt.Audience{jtiRegressionTokenURL},
		Expiry:   jwt.NewNumericDate(time.Now().UTC().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now().UTC()),
		ID:       id,
	}
}

func jtiRegressionAssertion(t *testing.T, key *rsa.PrivateKey, cl jwt.Claims) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: key, KeyID: jtiRegressionKeyID, Algorithm: string(jose.RS256)}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jwk}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	raw, err := jwt.Signed(sig).Claims(cl).CompactSerialize()
	require.NoError(t, err)
	return raw
}

func jtiRegressionAccessRequest(assertion string) *fosite.AccessRequest {
	req := fosite.NewAccessRequest(new(fosite.DefaultSession))
	req.Form = url.Values{"assertion": {assertion}}
	req.GrantTypes = []string{jtiRegressionGrantType}
	req.Client = &fosite.DefaultClient{GrantTypes: []string{jtiRegressionGrantType}}
	return req
}

// TestMarkJWTUsedForTimeReturnsJTIKnown ensures that when the jti was consumed by a
// concurrent request after this request passed the IsJWTUsed check, the replay is
// rejected with ErrJTIKnown (the same error code as the pre-check) and not with a
// generic server error.
func TestMarkJWTUsedForTimeReturnsJTIKnown(t *testing.T) {
	ctrl := gomock.NewController(t)
	store := internal.NewMockRFC7523KeyStorage(ctrl)
	handler := newJTIRegressionHandler(store)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := jose.JSONWebKey{Key: key.Public(), KeyID: jtiRegressionKeyID, Algorithm: string(jose.RS256), Use: "sig"}

	ctx := context.Background()
	claims := jtiRegressionClaims("my_token")
	req := jtiRegressionAccessRequest(jtiRegressionAssertion(t, key, claims))

	store.EXPECT().GetPublicKey(ctx, claims.Issuer, claims.Subject, jtiRegressionKeyID).Return(&pubKey, nil)
	store.EXPECT().GetPublicKeyScopes(ctx, claims.Issuer, claims.Subject, jtiRegressionKeyID).Return([]string{"fosite"}, nil)
	store.EXPECT().IsJWTUsed(ctx, claims.ID).Return(false, nil)
	store.EXPECT().MarkJWTUsedForTime(ctx, claims.ID, claims.Expiry.Time()).Return(fosite.ErrJTIKnown)

	err = handler.HandleTokenEndpointRequest(ctx, req)
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrJTIKnown), "expected ErrJTIKnown, got: %v", err)
	assert.False(t, errors.Is(err, fosite.ErrServerError), "expected no ErrServerError, got: %v", err)
}

// TestConcurrentRequestsWithSameJTIConsumeOnlyOnce ensures that the jti of a valid
// assertion is consumed exactly once, even when many requests race: exactly one
// request succeeds, all others are rejected with ErrJTIKnown.
func TestConcurrentRequestsWithSameJTIConsumeOnlyOnce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	store.IssuerPublicKeys[jtiRegressionIssuer] = storage.IssuerPublicKeys{
		Issuer: jtiRegressionIssuer,
		KeysBySub: map[string]storage.SubjectPublicKeys{
			jtiRegressionSubject: {
				Subject: jtiRegressionSubject,
				Keys: map[string]storage.PublicKeyScopes{
					jtiRegressionKeyID: {
						Key:    &jose.JSONWebKey{Key: key.Public(), KeyID: jtiRegressionKeyID, Algorithm: string(jose.RS256), Use: "sig"},
						Scopes: []string{"fosite"},
					},
				},
			},
		},
	}
	handler := newJTIRegressionHandler(store)

	assertion := jtiRegressionAssertion(t, key, jtiRegressionClaims("shared-jti"))

	const workers = 16
	start := make(chan struct{})
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = handler.HandleTokenEndpointRequest(context.Background(), jtiRegressionAccessRequest(assertion))
		}(i)
	}
	close(start)
	wg.Wait()

	var succeeded, replayed int
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, fosite.ErrJTIKnown):
			replayed++
		default:
			t.Errorf("unexpected error (must be nil or ErrJTIKnown): %v", err)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one request must consume the jti")
	assert.Equal(t, workers-1, replayed, "all other requests must be rejected as replays")

	// A later request with the same (already consumed) jti must keep being rejected.
	err = handler.HandleTokenEndpointRequest(context.Background(), jtiRegressionAccessRequest(assertion))
	assert.True(t, errors.Is(err, fosite.ErrJTIKnown), "expected ErrJTIKnown, got: %v", err)
}
