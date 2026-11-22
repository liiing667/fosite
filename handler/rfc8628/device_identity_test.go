// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc8628

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

// stubUserCodeStrategy returns user codes from a predefined list so that
// collisions between the user codes of two device authorization sessions can
// be simulated.
type stubUserCodeStrategy struct {
	RFC8628CodeStrategy
	codes []string
	idx   int
}

func (s *stubUserCodeStrategy) GenerateUserCode(ctx context.Context) (string, string, error) {
	code := s.codes[s.idx%len(s.codes)]
	s.idx++
	signature, err := s.UserCodeSignature(ctx, code)
	if err != nil {
		return "", "", err
	}
	return code, signature, nil
}

func newDeviceRequestForClient(clientID string) *fosite.DeviceRequest {
	return &fosite.DeviceRequest{
		Request: fosite.Request{
			Client:  &fosite.DefaultClient{ID: clientID},
			Session: &fosite.DefaultSession{},
		},
	}
}

// A second device authorization must never take over the user code of the
// first one. The user code, the device code and the client have to stay bound
// to the same device authorization session.
func TestDeviceAuthHandler_UserCodeCollisionKeepsIdentity(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	strategy := &stubUserCodeStrategy{
		RFC8628CodeStrategy: &RFC8628HMACSHAStrategy,
		codes:               []string{"SHARED-CODE", "SHARED-CODE", "SHARED-CODE", "UNIQUE-CODE"},
	}
	h := &DeviceAuthHandler{
		Storage:  store,
		Strategy: strategy,
		Config: &fosite.Config{
			DeviceAndUserCodeLifespan:      time.Minute * 10,
			DeviceAuthTokenPollingInterval: time.Second * 5,
			DeviceVerificationURL:          "https://example.com/device",
		},
	}

	resp1 := fosite.NewDeviceResponse()
	require.NoError(t, h.HandleDeviceEndpointRequest(ctx, newDeviceRequestForClient("first-client"), resp1))
	require.Equal(t, "SHARED-CODE", resp1.GetUserCode())

	// The second device authorization generates the already used user code on
	// the first attempts and must retry until a unique user code is found.
	resp2 := fosite.NewDeviceResponse()
	require.NoError(t, h.HandleDeviceEndpointRequest(ctx, newDeviceRequestForClient("second-client"), resp2))
	require.Equal(t, "UNIQUE-CODE", resp2.GetUserCode())

	// The first user code must still belong to the first client.
	sig1, err := strategy.UserCodeSignature(ctx, "SHARED-CODE")
	require.NoError(t, err)
	session1, err := store.GetDeviceCodeSession(ctx, sig1, nil)
	require.NoError(t, err)
	assert.Equal(t, "first-client", session1.GetClient().GetID())

	// The second user code belongs to the second client.
	sig2, err := strategy.UserCodeSignature(ctx, "UNIQUE-CODE")
	require.NoError(t, err)
	session2, err := store.GetDeviceCodeSession(ctx, sig2, nil)
	require.NoError(t, err)
	assert.Equal(t, "second-client", session2.GetClient().GetID())
}

// The store must reject a duplicate user code signature instead of silently
// re-binding it to another device authorization session.
func TestMemoryStore_DeviceAuthSessionDuplicateUserCode(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()

	require.NoError(t, store.CreateDeviceAuthSession(ctx, "device-code-signature-1", "user-code-signature", newDeviceRequestForClient("first-client")))

	err := store.CreateDeviceAuthSession(ctx, "device-code-signature-2", "user-code-signature", newDeviceRequestForClient("second-client"))
	require.ErrorIs(t, err, fosite.ErrExistingUserCodeSignature)

	// The original session is untouched.
	session, err := store.GetDeviceCodeSession(ctx, "user-code-signature", nil)
	require.NoError(t, err)
	assert.Equal(t, "first-client", session.GetClient().GetID())

	session, err = store.GetDeviceCodeSession(ctx, "device-code-signature-1", nil)
	require.NoError(t, err)
	assert.Equal(t, "first-client", session.GetClient().GetID())

	// The rejected session was not stored at all.
	_, err = store.GetDeviceCodeSession(ctx, "device-code-signature-2", nil)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

// After a device code has been used, both the device code and the user code
// stay bound to the original session and are reported as invalidated. A
// replayed poll fails with invalid_grant and revokes the issued tokens.
func TestDeviceCodeTokenEndpointHandler_InvalidationAndReplay(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemoryStore()
	strategy := &RFC8628HMACSHAStrategy

	h := DeviceCodeTokenEndpointHandler{
		DeviceRateLimitStrategy: strategy,
		DeviceCodeStrategy:      strategy,
		UserCodeStrategy:        strategy,
		CoreStorage:             store,
		AccessTokenStrategy:     hmacshaStrategy,
		RefreshTokenStrategy:    hmacshaStrategy,
		TokenRevocationStorage:  store,
		Config: &fosite.Config{
			ScopeStrategy:             fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:  fosite.DefaultAudienceMatchingStrategy,
			DeviceAndUserCodeLifespan: time.Minute * 10,
			AccessTokenLifespan:       time.Minute * 10,
			RefreshTokenLifespan:      time.Minute * 10,
		},
	}

	deviceCode, deviceCodeSignature, err := strategy.GenerateDeviceCode(ctx)
	require.NoError(t, err)
	_, userCodeSignature, err := strategy.GenerateUserCode(ctx)
	require.NoError(t, err)

	authreq := &fosite.DeviceRequest{
		UserCodeState: fosite.UserCodeAccepted,
		Request: fosite.Request{
			Client:         &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}},
			RequestedScope: fosite.Arguments{"foo", "offline"},
			GrantedScope:   fosite.Arguments{"foo", "offline"},
			Session:        &fosite.DefaultSession{},
			RequestedAt:    time.Now().UTC(),
		},
	}
	require.NoError(t, store.CreateDeviceAuthSession(ctx, deviceCodeSignature, userCodeSignature, authreq))

	newAccessRequest := func() *fosite.AccessRequest {
		return &fosite.AccessRequest{
			GrantTypes: fosite.Arguments{"urn:ietf:params:oauth:grant-type:device_code"},
			Request: fosite.Request{
				Form:        url.Values{"device_code": {deviceCode}},
				Client:      &fosite.DefaultClient{ID: "foo", GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"}},
				Session:     &fosite.DefaultSession{},
				RequestedAt: time.Now().UTC(),
			},
		}
	}

	// The first poll succeeds and issues tokens.
	areq := newAccessRequest()
	require.NoError(t, h.HandleTokenEndpointRequest(ctx, areq))
	aresp := fosite.NewAccessResponse()
	require.NoError(t, h.PopulateTokenEndpointResponse(ctx, areq, aresp))
	require.NotEmpty(t, aresp.AccessToken)
	refreshToken, ok := aresp.GetExtra("refresh_token").(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)
	require.NotEmpty(t, store.AccessTokens)

	// The used device code and its user code stay bound to the original
	// session and are reported as invalidated.
	replayed, err := store.GetDeviceCodeSession(ctx, deviceCodeSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInvalidatedDeviceCode)
	require.NotNil(t, replayed)
	assert.Equal(t, "foo", replayed.GetClient().GetID())

	_, err = store.GetDeviceCodeSession(ctx, userCodeSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInvalidatedDeviceCode)

	// The user code of a completed session cannot be reused by a new session.
	err = store.CreateDeviceAuthSession(ctx, "another-device-code-signature", userCodeSignature, newDeviceRequestForClient("bar"))
	require.ErrorIs(t, err, fosite.ErrExistingUserCodeSignature)

	// A replayed poll fails with invalid_grant and revokes the issued tokens.
	err = h.HandleTokenEndpointRequest(ctx, newAccessRequest())
	require.EqualError(t, err, fosite.ErrInvalidGrant.Error())
	assert.Empty(t, store.AccessTokens)

	refreshSignature := hmacshaStrategy.RefreshTokenSignature(ctx, refreshToken)
	_, err = store.GetRefreshTokenSession(ctx, refreshSignature, nil)
	require.ErrorIs(t, err, fosite.ErrInactiveToken)
}
