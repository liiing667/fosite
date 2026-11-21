// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package par_test

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite/storage"

	"github.com/ory/fosite"
	. "github.com/ory/fosite/handler/par"
)

func parseURL(uu string) *url.URL {
	u, _ := url.Parse(uu)
	return u
}

func TestAuthorizeCode_HandleAuthorizeEndpointRequest(t *testing.T) {
	requestURIPrefix := "urn:ietf:params:oauth:request_uri_diff:"
	store := storage.NewMemoryStore()
	handler := PushedAuthorizeHandler{
		Storage: store,
		Config: &fosite.Config{
			PushedAuthorizeContextLifespan:  30 * time.Minute,
			PushedAuthorizeRequestURIPrefix: requestURIPrefix,
			ScopeStrategy:                   fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:        fosite.DefaultAudienceMatchingStrategy,
		},
	}
	for _, c := range []struct {
		handler     PushedAuthorizeHandler
		areq        *fosite.AuthorizeRequest
		description string
		expectErr   error
		expect      func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.PushedAuthorizeResponse)
	}{
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{""},
				Request:       *fosite.NewRequest(),
			},
			description: "should pass because not responsible for handling an empty response type",
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"foo"},
				Request:       *fosite.NewRequest(),
			},
			description: "should pass because not responsible for handling an invalid response type",
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"code"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code"},
						RedirectURIs:  []string{"http://asdf.com/cb"},
					},
				},
				RedirectURI: parseURL("http://asdf.com/cb"),
			},
			description: "should fail because redirect uri is not https",
			expectErr:   fosite.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"code"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.com/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/not-api"},
				},
				RedirectURI: parseURL("https://asdf.com/cb"),
			},
			description: "should fail because audience doesn't match",
			expectErr:   fosite.ErrInvalidRequest,
		},
		{
			handler: handler,
			areq: &fosite.AuthorizeRequest{
				ResponseTypes: fosite.Arguments{"code"},
				Request: fosite.Request{
					Client: &fosite.DefaultClient{
						ResponseTypes: fosite.Arguments{"code"},
						RedirectURIs:  []string{"https://asdf.de/cb"},
						Audience:      []string{"https://www.ory.sh/api"},
					},
					RequestedAudience: []string{"https://www.ory.sh/api"},
					GrantedScope:      fosite.Arguments{"a", "b"},
					Session: &fosite.DefaultSession{
						ExpiresAt: map[fosite.TokenType]time.Time{fosite.AccessToken: time.Now().UTC().Add(time.Hour)},
					},
					RequestedAt: time.Now().UTC(),
				},
				State:       "superstate",
				RedirectURI: parseURL("https://asdf.de/cb"),
			},
			description: "should pass",
			expect: func(t *testing.T, areq *fosite.AuthorizeRequest, aresp *fosite.PushedAuthorizeResponse) {
				requestURI := aresp.RequestURI
				assert.NotEmpty(t, requestURI)
				assert.True(t, strings.HasPrefix(requestURI, requestURIPrefix), "requestURI does not match: %s", requestURI)
			},
		},
	} {
		t.Run("case="+c.description, func(t *testing.T) {
			aresp := &fosite.PushedAuthorizeResponse{}
			err := c.handler.HandlePushedAuthorizeEndpointRequest(context.Background(), c.areq, aresp)
			if c.expectErr != nil {
				require.EqualError(t, err, c.expectErr.Error())
			} else {
				require.NoError(t, err)
			}

			if c.expect != nil {
				c.expect(t, c.areq, aresp)
			}
		})
	}
}

// TestPushedAuthorizeRequestURIConsumedOnce verifies the whole PAR lifecycle
// against the memory storage: a stored PAR session can only be consumed once,
// even when many goroutines try to consume the same request_uri at the same
// time.
func TestPushedAuthorizeRequestURIConsumedOnce(t *testing.T) {
	requestURIPrefix := "urn:ietf:params:oauth:request_uri_diff:"
	store := storage.NewMemoryStore()
	handler := PushedAuthorizeHandler{
		Storage: store,
		Config: &fosite.Config{
			PushedAuthorizeContextLifespan:  time.Hour,
			PushedAuthorizeRequestURIPrefix: requestURIPrefix,
			ScopeStrategy:                   fosite.HierarchicScopeStrategy,
			AudienceMatchingStrategy:        fosite.DefaultAudienceMatchingStrategy,
		},
	}

	redir := parseURL("https://asdf.de/cb")
	areq := &fosite.AuthorizeRequest{
		ResponseTypes: fosite.Arguments{"code"},
		Request: fosite.Request{
			Client: &fosite.DefaultClient{
				ResponseTypes: fosite.Arguments{"code"},
				RedirectURIs:  []string{"https://asdf.de/cb"},
				Audience:      []string{"https://www.ory.sh/api"},
			},
			RequestedAudience: []string{"https://www.ory.sh/api"},
			RequestedAt:       time.Now().UTC(),
			Session:           &fosite.DefaultSession{},
		},
		State:       "superstate",
		RedirectURI: redir,
	}

	// Push the authorization request.
	aresp := &fosite.PushedAuthorizeResponse{}
	require.NoError(t, handler.HandlePushedAuthorizeEndpointRequest(context.Background(), areq, aresp))
	requestURI := aresp.GetRequestURI()
	require.NotEmpty(t, requestURI)

	consumer, ok := handler.Storage.(fosite.PARSessionConsumer)
	require.True(t, ok, "the memory storage must support atomic PAR session consumption")

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

			_, err := consumer.ConsumePARSession(context.Background(), requestURI)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, fosite.ErrNotFound):
				failures++
			default:
				otherErrs++
				assert.NoError(t, err)
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, 1, successes)
	assert.Equal(t, goroutines-1, failures)
	assert.Equal(t, 0, otherErrs)

	// The request_uri stays unavailable after the concurrent consumption burst.
	_, err := consumer.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

// TestPushedAuthorizeRequestURIExpired verifies that an expired PAR session
// cannot be consumed.
func TestPushedAuthorizeRequestURIExpired(t *testing.T) {
	requestURIPrefix := "urn:ietf:params:oauth:request_uri_diff:"
	store := storage.NewMemoryStore()

	requestURI := requestURIPrefix + "expired"
	expired := fosite.NewAuthorizeRequest()
	expired.Session = &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.PushedAuthorizeRequestContext: time.Now().UTC().Add(-time.Second),
		},
	}
	require.NoError(t, store.CreatePARSession(context.Background(), requestURI, expired))

	consumer, ok := store.(fosite.PARSessionConsumer)
	require.True(t, ok)

	got, err := consumer.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	assert.Nil(t, got)
}
