// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
	RefreshTokenStrategy   RefreshTokenStrategy
	AccessTokenStrategy    AccessTokenStrategy
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) error {
	discoveryFuncs := []func() (request fosite.Requester, tokenUse fosite.TokenUse, signature string, err error){
		func() (request fosite.Requester, tokenUse fosite.TokenUse, signature string, err error) {
			// Refresh token
			refreshSignature := r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
			request, err = r.TokenRevocationStorage.GetRefreshTokenSession(ctx, refreshSignature, nil)
			return request, fosite.RefreshToken, refreshSignature, err
		},
		func() (request fosite.Requester, tokenUse fosite.TokenUse, signature string, err error) {
			// Access token
			accessSignature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
			request, err = r.TokenRevocationStorage.GetAccessTokenSession(ctx, accessSignature, nil)
			return request, fosite.AccessToken, accessSignature, err
		},
	}

	// Token type hinting
	if tokenType == fosite.AccessToken {
		discoveryFuncs[0], discoveryFuncs[1] = discoveryFuncs[1], discoveryFuncs[0]
	}

	var ar fosite.Requester
	var matchedTokenUse fosite.TokenUse
	var matchedSignature string
	var err1, err2 error
	if ar, matchedTokenUse, matchedSignature, err1 = discoveryFuncs[0](); err1 != nil {
		ar, matchedTokenUse, matchedSignature, err2 = discoveryFuncs[1]()
	}
	// err2 can only be not nil if first err1 was not nil
	if err2 != nil {
		noSession := (errors.Is(err1, fosite.ErrNotFound) || errors.Is(err1, fosite.ErrInactiveToken)) &&
			(errors.Is(err2, fosite.ErrNotFound) || errors.Is(err2, fosite.ErrInactiveToken))
		if noSession && r.revokeStatelessJWT(ctx, token, client) {
			return nil
		}
		return storeErrorsToRevocationError(err1, err2)
	}

	if ar.GetClient().GetID() != client.GetID() {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient)
	}

	requestID := ar.GetID()
	err1 = r.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
	err2 = r.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)

	if err := storeErrorsToRevocationError(err1, err2); err != nil {
		return err
	}

	r.recordRevocation(ctx, token, matchedSignature, matchedTokenUse, client, requestID, ar)
	return nil
}

func (r *TokenRevocationHandler) revokeStatelessJWT(ctx context.Context, token string, client fosite.Client) bool {
	validator, ok := r.AccessTokenStrategy.(interface {
		ValidateToken(ctx context.Context, token string) (clientID string, expiresAt time.Time, err error)
	})
	if !ok {
		return false
	}
	clientID, expiresAt, err := validator.ValidateToken(ctx, token)
	if err != nil {
		return false
	}
	if clientID != "" && clientID != client.GetID() {
		return false
	}

	signature := r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenRevocationRecorder); ok {
		_ = recorder.RecordTokenRevocation(ctx, fosite.TokenRevocationRecord{
			TokenDigest:    fosite.TokenDigest(token),
			TokenSignature: signature,
			ClientID:       client.GetID(),
			TokenUse:       fosite.AccessToken,
			RevokedAt:      time.Now().UTC(),
			ExpiresAt:      expiresAt,
			Source:         "token-revocation-handler-stateless",
		})
	}
	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenSignatureRevocationRecorder); ok {
		_ = recorder.RecordTokenSignatureRevocation(ctx, signature, expiresAt)
	}
	return true
}

func (r *TokenRevocationHandler) recordRevocation(
	ctx context.Context,
	token string,
	signature string,
	tokenUse fosite.TokenUse,
	client fosite.Client,
	requestID string,
	request fosite.Requester,
) {
	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenRevocationRecorder); ok {
		_ = recorder.RecordTokenRevocation(ctx, fosite.TokenRevocationRecord{
			TokenDigest:    fosite.TokenDigest(token),
			TokenSignature: signature,
			ClientID:       client.GetID(),
			TokenUse:       tokenUse,
			RequestID:      requestID,
			RevokedAt:      time.Now().UTC(),
			ExpiresAt:      revocationExpiry(request, tokenUse),
			Source:         "token-revocation-handler",
		})
	}
	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenSignatureRevocationRecorder); ok {
		_ = recorder.RecordTokenSignatureRevocation(ctx, signature, revocationExpiry(request, tokenUse))
	}
}

func revocationExpiry(request fosite.Requester, tokenUse fosite.TokenUse) time.Time {
	if request == nil || request.GetSession() == nil {
		return time.Time{}
	}
	return request.GetSession().GetExpiresAt(tokenUse)
}

func storeErrorsToRevocationError(err1, err2 error) error {
	// both errors are fosite.ErrNotFound and fosite.ErrInactiveToken or nil <=> the token is revoked
	if (errors.Is(err1, fosite.ErrNotFound) || errors.Is(err1, fosite.ErrInactiveToken) || err1 == nil) &&
		(errors.Is(err2, fosite.ErrNotFound) || errors.Is(err2, fosite.ErrInactiveToken) || err2 == nil) {
		return nil
	}

	// there was an unexpected error => the token may still exist and the client should retry later
	return errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
}
