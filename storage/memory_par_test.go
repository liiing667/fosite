// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func newPARSession(expiresAt time.Time) *fosite.AuthorizeRequest {
	req := fosite.NewAuthorizeRequest()
	req.RequestedAt = time.Now().UTC()
	req.Session = &fosite.DefaultSession{
		ExpiresAt: map[fosite.TokenType]time.Time{
			fosite.PushedAuthorizeRequestContext: expiresAt,
		},
	}
	return req
}

func TestMemoryStore_ConsumePARSessionNotFound(t *testing.T) {
	s := NewMemoryStore()

	got, err := s.ConsumePARSession(context.Background(), "urn:ietf:params:oauth:request_uri:does-not-exist")
	require.ErrorIs(t, err, fosite.ErrNotFound)
	assert.Nil(t, got)
}

func TestMemoryStore_ConsumePARSessionDeletesAfterRead(t *testing.T) {
	s := NewMemoryStore()
	requestURI := "urn:ietf:params:oauth:request_uri:once"
	par := newPARSession(time.Now().UTC().Add(time.Hour))

	require.NoError(t, s.CreatePARSession(context.Background(), requestURI, par))

	got, err := s.ConsumePARSession(context.Background(), requestURI)
	require.NoError(t, err)
	assert.Same(t, par, got)

	// The session must be gone after consumption.
	_, err = s.GetPARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)

	// A second consumption attempt must fail even though the first one succeeded.
	_, err = s.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_ConsumePARSessionRejectsExpiredSession(t *testing.T) {
	s := NewMemoryStore()
	requestURI := "urn:ietf:params:oauth:request_uri:expired"
	par := newPARSession(time.Now().UTC().Add(-time.Second))

	require.NoError(t, s.CreatePARSession(context.Background(), requestURI, par))

	// Expired PAR sessions must never be consumable.
	got, err := s.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
	assert.Nil(t, got)

	// The expired session is removed, so it stays unavailable.
	_, err = s.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_ConsumePARSessionIsConsumedExactlyOnceConcurrently(t *testing.T) {
	s := NewMemoryStore()
	requestURI := "urn:ietf:params:oauth:request_uri:concurrent"
	par := newPARSession(time.Now().UTC().Add(time.Hour))

	require.NoError(t, s.CreatePARSession(context.Background(), requestURI, par))

	const goroutines = 64
	var (
		wg        sync.WaitGroup
		successes int64
		notFounds int64
		otherErrs int64
		mu        sync.Mutex
		start     = make(chan struct{})
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start

			got, err := s.ConsumePARSession(context.Background(), requestURI)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				assert.Same(t, par, got)
				successes++
			case errors.Is(err, fosite.ErrNotFound):
				notFounds++
			default:
				otherErrs++
			}
		}()
	}

	close(start)
	wg.Wait()

	assert.Equal(t, int64(1), successes, "exactly one concurrent consumer must win")
	assert.Equal(t, int64(goroutines-1), notFounds, "all losing consumers must receive ErrNotFound")
	assert.Equal(t, int64(0), otherErrs, "no unexpected errors must occur")

	// The request_uri remains unavailable after the concurrent burst.
	_, err := s.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}

func TestMemoryStore_PARSessionSurvivesUntilConsumedOrExpiry(t *testing.T) {
	s := NewMemoryStore()
	requestURI := "urn:ietf:params:oauth:request_uri:restart"
	par := newPARSession(time.Now().UTC().Add(time.Hour))

	require.NoError(t, s.CreatePARSession(context.Background(), requestURI, par))

	// Simulate a process restart: nothing is proactively removed while the
	// session is unconsumed and unexpired, so it must still be consumable once.
	got, err := s.ConsumePARSession(context.Background(), requestURI)
	require.NoError(t, err)
	assert.Same(t, par, got)

	// After consumption (or expiry) a restart must not resurrect the session.
	_, err = s.ConsumePARSession(context.Background(), requestURI)
	require.ErrorIs(t, err, fosite.ErrNotFound)
}
