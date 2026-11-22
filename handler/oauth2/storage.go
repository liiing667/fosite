// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"

	"github.com/ory/fosite"
)

type CoreStorage interface {
	AuthorizeCodeStorage
	AccessTokenStorage
	RefreshTokenStorage
}

// AuthorizeCodeStorage handles storage requests related to authorization codes.
type AuthorizeCodeStorage interface {
	// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
	CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error)

	// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
	// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
	// method should return the ErrInvalidatedAuthorizeCode error.
	//
	// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedAuthorizeCode error!
	GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error)

	// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
	// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
	// ErrInvalidatedAuthorizeCode error.
	//
	// This call is the final commit point for an authorization-code exchange.
	// Implementations must make the transition atomic and must return
	// fosite.ErrInvalidatedAuthorizeCode (instead of nil) when the code has
	// already been invalidated. That guarantee is what allows concurrent
	// exchanges of the same code to succeed at most once.
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
}

// AuthorizeCodeConsumer is an optional extension of AuthorizeCodeStorage. It
// atomically consumes an authorization code and returns the authorization
// request that was stored with it.
//
// Consumers must return fosite.ErrInvalidatedAuthorizeCode (and the stored
// requester) when the code has already been consumed. The handler uses this
// interface when it is available so that concurrent exchanges cannot both
// create a token. Stores that do not implement it fall back to the atomic
// InvalidateAuthorizeCodeSession contract.
type AuthorizeCodeConsumer interface {
	ConsumeAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error)
}

// AuthorizeCodeSessionConsumer is an alias for AuthorizeCodeConsumer.
type AuthorizeCodeSessionConsumer = AuthorizeCodeConsumer

// AuthorizeCodeStorageConsumer is an alias for AuthorizeCodeConsumer.
type AuthorizeCodeStorageConsumer = AuthorizeCodeConsumer

// AuthorizeCodeTombstoneStorage is an optional extension used when the claim
// itself fails. It lets a store persist a fail-closed tombstone so that a
// retry cannot redeem a code whose consumption transaction failed halfway.
type AuthorizeCodeTombstoneStorage interface {
	TombstoneAuthorizeCodeSession(ctx context.Context, code string, reason string) error
}

type AccessTokenStorage interface {
	CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error)

	GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteAccessTokenSession(ctx context.Context, signature string) (err error)
}

type RefreshTokenStorage interface {
	CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) (err error)

	GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error)

	DeleteRefreshTokenSession(ctx context.Context, signature string) (err error)

	RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error)
}
