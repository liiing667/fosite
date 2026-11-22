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
	InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error)
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

	// RotateRefreshToken invalidates the refresh token identified by
	// `refreshTokenSignature` - the generation that was presented by the client -
	// together with the access token that was issued alongside it, before a new
	// generation is created with `CreateRefreshTokenSession`.
	//
	// Implementations should pin the rotation to the token family (`requestID`)
	// and the presented generation (`refreshTokenSignature`): if the presented
	// token is unknown, belongs to a different family, or was already rotated,
	// an error (e.g. fosite.ErrNotFound or fosite.ErrInactiveToken) should be
	// returned and no other token of the family should be touched. This
	// guarantees that a refresh token family keeps exactly one valid generation
	// at any time, even under concurrent use, after a failed rotation, or after
	// a restart.
	RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error)
}
