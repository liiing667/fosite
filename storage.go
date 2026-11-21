// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "context"

// Storage defines fosite's minimal storage interface.
type Storage interface {
	ClientManager
}

// PARStorage holds information needed to store and retrieve PAR context.
type PARStorage interface {
	// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
	CreatePARSession(ctx context.Context, requestURI string, request AuthorizeRequester) error
	// GetPARSession gets the push authorization request context. The caller is expected to merge the AuthorizeRequest.
	GetPARSession(ctx context.Context, requestURI string) (AuthorizeRequester, error)
	// DeletePARSession deletes the context.
	DeletePARSession(ctx context.Context, requestURI string) (err error)
}

// PARSessionConsumer is an optional extension of PARStorage which atomically
// retrieves and deletes a pushed authorization request context.
//
// Implementing this interface guarantees that a PAR request_uri can only be
// consumed once, even when multiple authorization requests are processed
// concurrently. If a storage implementation does not implement this
// interface, fosite falls back to the non-atomic GetPARSession /
// DeletePARSession combination for backwards compatibility.
type PARSessionConsumer interface {
	// ConsumePARSession atomically retrieves and deletes the pushed
	// authorization request context stored under requestURI.
	//
	// It must return ErrNotFound when no (unconsumed) session exists for the
	// requestURI, including when the session was already consumed or has
	// expired. A successful call removes the session so that any subsequent
	// call for the same requestURI fails.
	ConsumePARSession(ctx context.Context, requestURI string) (AuthorizeRequester, error)
}
