// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

const parTestRequestURIPrefix = "urn:ietf:params:oauth:request_uri:"

func newPARTestFosite(t *testing.T, lifespan time.Duration) (*fosite.Fosite, *storage.MemoryStore) {
	t.Helper()

	store := storage.NewMemoryStore()
	store.Clients["par-client"] = &fosite.DefaultClient{
		ID:            "par-client",
		RedirectURIs:  []string{"https://foo.bar/cb"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"fosite", "openid"},
	}

	f := &fosite.Fosite{
		Store: store,
		Config: &fosite.Config{
			ScopeStrategy:                   fosite.ExactScopeStrategy,
			AudienceMatchingStrategy:        fosite.DefaultAudienceMatchingStrategy,
			PushedAuthorizeRequestURIPrefix: parTestRequestURIPrefix,
			PushedAuthorizeContextLifespan:  lifespan,
		},
	}

	return f, store
}

func newPARAuthorizeRequest(t *testing.T, expiresAt time.Time) *fosite.AuthorizeRequest {
	t.Helper()

	redir, err := url.Parse("https://foo.bar/cb")
	require.NoError(t, err)

	req := fosite.NewAuthorizeRequest()
	req.Client = &fosite.DefaultClient{ID: "par-client"}
	req.RedirectURI = redir
	req.ResponseTypes = fosite.Arguments{"code"}
	req.State = "par-state"
	req.RequestedAt = time.Now().UTC()
	req.Form = url.Values{
		"client_id":     []string{"par-client"},
		"response_type": []string{"code"},
		"redirect_uri":  []string{"https://foo.bar/cb"},
		"state":         []string{"par-state"},
		"scope":         []string{"fosite"},
	}
	req.Session = &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.PushedAuthorizeRequestContext: expiresAt,
		},
	}

	return req
}

func newPARConsumptionHTTPRequest(requestURI string) *http.Request {
	return newPARConsumptionHTTPRequestWithClient(requestURI, "par-client")
}

func newPARConsumptionHTTPRequestWithClient(requestURI, clientID string) *http.Request {
	query := url.Values{
		"client_id":   []string{clientID},
		"request_uri": []string{requestURI},
	}
	return &http.Request{
		Method: http.MethodGet,
		Header: http.Header{},
		URL: &url.URL{
			Scheme:   "https",
			Host:     "foo.bar",
			Path:     "/oauth2/auth",
			RawQuery: query.Encode(),
		},
	}
}

// TestNewAuthorizeRequestPARConsumedOnce ensures that a PAR request_uri can
// only be consumed once when multiple authorization requests arrive
// concurrently.
func TestNewAuthorizeRequestPARConsumedOnce(t *testing.T) {
	f, store := newPARTestFosite(t, time.Hour)

	requestURI := parTestRequestURIPrefix + "concurrent-once"
	par := newPARAuthorizeRequest(t, time.Now().UTC().Add(time.Hour))
	require.NoError(t, store.CreatePARSession(context.Background(), requestURI, par))

	const goroutines = 32
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		failures  int
		otherErrs int
		start     = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start

			_, err := f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))

			mu.Lock()
			defer mu.Unlock()
			var rfcErr *fosite.RFC6749Error
			switch {
			case err == nil:
				successes++
			case errors.As(err, &rfcErr):
				failures++
			default:
				otherErrs++
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, 1, successes, "exactly one concurrent authorization request must succeed")
	assert.Equal(t, goroutines-1, failures, "all other concurrent authorization requests must fail")
	assert.Equal(t, 0, otherErrs)

	// The request_uri must stay unavailable after the concurrent burst.
	_, err := f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.Equal(t, fosite.ErrInvalidRequestURI.ErrorField, rfcErr.ErrorField)
}

// TestNewAuthorizeRequestPARSequentialReplay ensures that even sequential
// re-use of a request_uri is rejected after the first successful consumption.
func TestNewAuthorizeRequestPARSequentialReplay(t *testing.T) {
	f, store := newPARTestFosite(t, time.Hour)

	requestURI := parTestRequestURIPrefix + "sequential-once"
	par := newPARAuthorizeRequest(t, time.Now().UTC().Add(time.Hour))
	require.NoError(t, store.CreatePARSession(context.Background(), requestURI, par))

	ar, err := f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.NoError(t, err)
	assert.Equal(t, "par-state", ar.GetState())
	assert.Equal(t, fosite.Arguments{"code"}, ar.GetResponseTypes())

	_, err = f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.Equal(t, fosite.ErrInvalidRequestURI.ErrorField, rfcErr.ErrorField)
}

// TestNewAuthorizeRequestPARExpired ensures expired PAR sessions cannot be
// consumed and report the same invalid_request_uri error as unknown sessions.
func TestNewAuthorizeRequestPARExpired(t *testing.T) {
	f, store := newPARTestFosite(t, time.Hour)

	requestURI := parTestRequestURIPrefix + "expired"
	par := newPARAuthorizeRequest(t, time.Now().UTC().Add(-time.Second))
	require.NoError(t, store.CreatePARSession(context.Background(), requestURI, par))

	_, err := f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.Equal(t, fosite.ErrInvalidRequestURI.ErrorField, rfcErr.ErrorField)
}

// TestNewAuthorizeRequestPARClientMismatch keeps the existing client
// validation behavior: the request_uri is consumed, but a mismatching
// client_id is rejected with ErrInvalidRequest.
func TestNewAuthorizeRequestPARClientMismatch(t *testing.T) {
	f, store := newPARTestFosite(t, time.Hour)

	requestURI := parTestRequestURIPrefix + "client-mismatch"
	par := newPARAuthorizeRequest(t, time.Now().UTC().Add(time.Hour))
	require.NoError(t, store.CreatePARSession(context.Background(), requestURI, par))

	r := newPARConsumptionHTTPRequestWithClient(requestURI, "some-other-client")

	_, err := f.NewAuthorizeRequest(context.Background(), r)
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.Equal(t, fosite.ErrInvalidRequest.ErrorField, rfcErr.ErrorField)

	// Even though the client did not match, the request_uri was consumed and
	// cannot be replayed by the legitimate client.
	_, err = f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.Error(t, err)
}

// legacyPARStore implements exactly the pre-existing fosite.Storage and
// fosite.PARStorage surfaces (no PARSessionConsumer), emulating storage
// implementations that have not yet been upgraded to atomic consumption.
type legacyPARStore struct {
	inner *storage.MemoryStore
}

func (l *legacyPARStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return l.inner.GetClient(ctx, id)
}

func (l *legacyPARStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return l.inner.ClientAssertionJWTValid(ctx, jti)
}

func (l *legacyPARStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return l.inner.SetClientAssertionJWT(ctx, jti, exp)
}

func (l *legacyPARStore) CreatePARSession(
	ctx context.Context, requestURI string, request fosite.AuthorizeRequester,
) error {
	return l.inner.CreatePARSession(ctx, requestURI, request)
}

func (l *legacyPARStore) GetPARSession(
	ctx context.Context, requestURI string,
) (fosite.AuthorizeRequester, error) {
	return l.inner.GetPARSession(ctx, requestURI)
}

func (l *legacyPARStore) DeletePARSession(ctx context.Context, requestURI string) error {
	return l.inner.DeletePARSession(ctx, requestURI)
}

var (
	_ fosite.Storage    = (*legacyPARStore)(nil)
	_ fosite.PARStorage = (*legacyPARStore)(nil)
)

// TestNewAuthorizeRequestPARLegacyStorageFallback keeps the non-atomic
// GetPARSession/DeletePARSession fallback working for storage implementations
// that only implement PARStorage, preserving backwards compatibility and the
// existing error codes.
func TestNewAuthorizeRequestPARLegacyStorageFallback(t *testing.T) {
	base := storage.NewMemoryStore()
	base.Clients["par-client"] = &fosite.DefaultClient{
		ID:            "par-client",
		RedirectURIs:  []string{"https://foo.bar/cb"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"fosite", "openid"},
	}

	f := &fosite.Fosite{
		Store: &legacyPARStore{inner: base},
		Config: &fosite.Config{
			ScopeStrategy:                   fosite.ExactScopeStrategy,
			AudienceMatchingStrategy:        fosite.DefaultAudienceMatchingStrategy,
			PushedAuthorizeRequestURIPrefix: parTestRequestURIPrefix,
			PushedAuthorizeContextLifespan:  time.Hour,
		},
	}

	requestURI := parTestRequestURIPrefix + "legacy-fallback"
	par := newPARAuthorizeRequest(t, time.Now().UTC().Add(time.Hour))
	require.NoError(t, base.CreatePARSession(context.Background(), requestURI, par))

	ar, err := f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.NoError(t, err)
	assert.Equal(t, "par-state", ar.GetState())

	// The wrapper really does not support atomic consumption.
	_, supportsConsumer := f.Store.(fosite.PARSessionConsumer)
	assert.False(t, supportsConsumer)

	// The legacy path still deletes the session after reading it.
	_, err = base.GetPARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)

	// Replaying the request_uri fails with the same invalid_request_uri error.
	_, err = f.NewAuthorizeRequest(context.Background(), newPARConsumptionHTTPRequest(requestURI))
	require.Error(t, err)

	var rfcErr *fosite.RFC6749Error
	require.True(t, errors.As(err, &rfcErr))
	assert.Equal(t, fosite.ErrInvalidRequestURI.ErrorField, rfcErr.ErrorField)
}
