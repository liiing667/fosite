// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

var _ fosite.TokenEndpointHandler = (*RefreshTokenGrantHandler)(nil)

type RefreshTokenGrantHandler struct {
	AccessTokenStrategy    AccessTokenStrategy
	RefreshTokenStrategy   RefreshTokenStrategy
	TokenRevocationStorage TokenRevocationStorage
	Config                 interface {
		fosite.AccessTokenLifespanProvider
		fosite.RefreshTokenLifespanProvider
		fosite.ScopeStrategyProvider
		fosite.AudienceStrategyProvider
		fosite.RefreshTokenScopesProvider
	}
}

// HandleTokenEndpointRequest implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant 'refresh_token'."))
	}

	refresh := request.GetRequestForm().Get("refresh_token")
	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, refresh)
	originalRequest, err := c.TokenRevocationStorage.GetRefreshTokenSession(ctx, signature, request.GetSession())
	if errors.Is(err, fosite.ErrInactiveToken) {
		// If the family already carries a revocation tombstone, the token was
		// revoked (rather than merely rotated). Do not run the reuse cleanup
		// again; the whole family is already fail-closed and a retry must not
		// be able to resurrect any part of it.
		if originalRequest != nil {
			revoked, checkErr := tokenFamilyRevoked(ctx, c.TokenRevocationStorage, originalRequest.GetID())
			if checkErr != nil {
				return fosite.ErrServerError.WithWrap(checkErr).WithDebug(checkErr.Error())
			}
			if revoked {
				return fosite.ErrInvalidGrant.WithWrap(err).
					WithHint("The refresh token family has been revoked.")
			}
		}

		// Detected refresh token reuse
		if rErr := c.handleRefreshTokenReuse(ctx, signature, originalRequest); rErr != nil {
			return errorsx.WithStack(rErr)
		}

		return fosite.ErrInvalidGrant.WithWrap(err).
			WithHint("The refresh token was already used.").
			WithDebugf("Refresh token re-use was detected. All related tokens have been revoked.")
	} else if errors.Is(err, fosite.ErrNotFound) {
		return fosite.ErrInvalidGrant.WithWrap(err).
			WithHint("The refresh token is malformed or not valid.").
			WithDebug("The refresh token can not be found.")
	} else if err != nil {
		return fosite.ErrServerError.WithWrap(err).WithDebug(err.Error())
	}

	if originalRequest != nil {
		if revoked, checkErr := tokenFamilyRevoked(ctx, c.TokenRevocationStorage, originalRequest.GetID()); checkErr != nil {
			return fosite.ErrServerError.WithWrap(checkErr).WithDebug(checkErr.Error())
		} else if revoked {
			return fosite.ErrInvalidGrant.WithWrap(fosite.ErrInactiveToken).
				WithHint("The refresh token family has been revoked.")
		}
	}

	if err := c.RefreshTokenStrategy.ValidateRefreshToken(ctx, originalRequest, refresh); err != nil {
		// The authorization server MUST ... validate the refresh token.
		// This needs to happen after store retrieval for the session to be hydrated properly
		if errors.Is(err, fosite.ErrTokenExpired) {
			return fosite.ErrInvalidGrant.WithWrap(err).
				WithHint("The refresh token expired.")
		}
		return fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error())
	}

	if !(len(c.Config.GetRefreshTokenScopes(ctx)) == 0 || originalRequest.GetGrantedScopes().HasOneOf(c.Config.GetRefreshTokenScopes(ctx)...)) {
		scopeNames := strings.Join(c.Config.GetRefreshTokenScopes(ctx), " or ")
		hint := fmt.Sprintf("The OAuth 2.0 Client was not granted scope %s and may thus not perform the 'refresh_token' authorization grant.", scopeNames)
		return errorsx.WithStack(fosite.ErrScopeNotGranted.WithHint(hint))
	}

	// The authorization server MUST ... and ensure that the refresh token was issued to the authenticated client
	if originalRequest.GetClient().GetID() != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetID(originalRequest.GetID())
	request.SetSession(originalRequest.GetSession().Clone())
	request.SetRequestedScopes(originalRequest.GetRequestedScopes())
	request.SetRequestedAudience(originalRequest.GetRequestedAudience())

	for _, scope := range originalRequest.GetGrantedScopes() {
		if !c.Config.GetScopeStrategy(ctx)(request.GetClient().GetScopes(), scope) {
			return errorsx.WithStack(fosite.ErrInvalidScope.WithHintf("The OAuth 2.0 Client is not allowed to request scope '%s'.", scope))
		}
		request.GrantScope(scope)
	}

	if err := c.Config.GetAudienceStrategy(ctx)(request.GetClient().GetAudience(), originalRequest.GetGrantedAudience()); err != nil {
		return err
	}

	for _, audience := range originalRequest.GetGrantedAudience() {
		request.GrantAudience(audience)
	}

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeRefreshToken, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

// PopulateTokenEndpointResponse implements https://tools.ietf.org/html/rfc6749#section-6
func (c *RefreshTokenGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	accessToken, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	refreshToken, refreshSignature, err := c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	signature := c.RefreshTokenStrategy.RefreshTokenSignature(ctx, requester.GetRequestForm().Get("refresh_token"))

	if revoked, checkErr := tokenFamilyRevoked(ctx, c.TokenRevocationStorage, requester.GetID()); checkErr != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(checkErr).WithDebug(checkErr.Error()))
	} else if revoked {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithWrap(fosite.ErrInactiveToken).
			WithHint("The refresh token family has been revoked."))
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	storeReq := requester.Sanitize([]string{})
	storeReq.SetID(requester.GetID())

	if err = c.TokenRevocationStorage.RotateRefreshToken(ctx, requester.GetID(), signature); err != nil {
		if !errors.Is(err, fosite.ErrNotFound) && !errors.Is(err, fosite.ErrInactiveToken) {
			return c.handlePartialRefreshStorageError(ctx, requester.GetID(), err)
		}
		return c.handleRefreshTokenEndpointStorageError(ctx, err)
	}

	if err = c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, storeReq); err != nil {
		return c.handlePartialRefreshStorageError(ctx, requester.GetID(), err)
	}

	if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, storeReq); err != nil {
		return c.handlePartialRefreshStorageError(ctx, requester.GetID(), err)
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return c.handlePartialRefreshStorageError(ctx, requester.GetID(), err)
	}

	return nil
}

// handlePartialRefreshStorageError rolls back a fully transactional refresh
// rotation. Stores without transactions cannot roll back the already completed
// rotation, so they must leave a family tombstone instead. This prevents a
// failed second storage step from exposing a newly created access token while
// the refresh token chain is already half-consumed.
func (c *RefreshTokenGrantHandler) handlePartialRefreshStorageError(ctx context.Context, requestID string, storageErr error) error {
	_, transactional := c.TokenRevocationStorage.(storage.Transactional)
	mappedErr := c.handleRefreshTokenEndpointStorageError(ctx, storageErr)
	if transactional || requestID == "" {
		return mappedErr
	}

	if revoker, ok := c.TokenRevocationStorage.(fosite.TokenFamilyRevoker); ok {
		if revokeErr := revoker.RevokeTokenFamily(ctx, requestID); revokeErr != nil {
			return errorsx.WithStack(fosite.ErrServerError.
				WithWrap(mappedErr).
				WithDebugf("error: %s; family revocation error: %s", mappedErr, revokeErr))
		}
	} else {
		// Legacy stores can still be made fail-closed: revoking the refresh
		// token first writes the family tombstone in implementations that
		// support it, and the access token cleanup removes the token that was
		// created before the second storage step failed.
		_ = c.TokenRevocationStorage.RevokeRefreshToken(ctx, requestID)
		_ = c.TokenRevocationStorage.RevokeAccessToken(ctx, requestID)
	}
	return mappedErr
}

// Reference: https://tools.ietf.org/html/rfc6819#section-5.2.2.3
//
//	The basic idea is to change the refresh token
//	value with every refresh request in order to detect attempts to
//	obtain access tokens using old refresh tokens.  Since the
//	authorization server cannot determine whether the attacker or the
//	legitimate client is trying to access, in case of such an access
//	attempt the valid refresh token and the access authorization
//	associated with it are both revoked.
func (c *RefreshTokenGrantHandler) handleRefreshTokenReuse(ctx context.Context, signature string, req fosite.Requester) (err error) {
	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	defer func() {
		err = c.handleRefreshTokenEndpointStorageError(ctx, err)
	}()

	if revoker, ok := c.TokenRevocationStorage.(fosite.TokenFamilyRevoker); ok && req != nil && req.GetID() != "" {
		if revokeErr := revoker.RevokeTokenFamily(ctx, req.GetID()); revokeErr != nil &&
			!errors.Is(revokeErr, fosite.ErrNotFound) &&
			!errors.Is(revokeErr, fosite.ErrInactiveToken) {
			return revokeErr
		}
		if err := storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
			return err
		}
		return nil
	}

	// Attempt every cleanup step. A refresh token has already been rotated
	// out, so the request must fail closed even if one of the cleanup calls
	// fails. If the refresh family itself was revoked successfully, reporting
	// invalid_grant is more accurate (and safer) than turning a storage error
	// into a retryable server error that leaves the caller guessing.
	var firstErr error
	familyRevoked := false
	if cleanupErr := c.TokenRevocationStorage.DeleteRefreshTokenSession(ctx, signature); cleanupErr != nil {
		firstErr = cleanupErr
	}
	if cleanupErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, req.GetID()); cleanupErr != nil &&
		!errors.Is(cleanupErr, fosite.ErrNotFound) &&
		!errors.Is(cleanupErr, fosite.ErrInactiveToken) {
		if firstErr == nil {
			firstErr = cleanupErr
		}
	} else {
		familyRevoked = true
	}
	if cleanupErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, req.GetID()); cleanupErr != nil &&
		!errors.Is(cleanupErr, fosite.ErrNotFound) &&
		!errors.Is(cleanupErr, fosite.ErrInactiveToken) {
		if firstErr == nil {
			firstErr = cleanupErr
		}
	}

	if firstErr != nil && !familyRevoked {
		err = firstErr
		return err
	}

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return err
	}

	return nil
}

func (c *RefreshTokenGrantHandler) handleRefreshTokenEndpointStorageError(ctx context.Context, storageErr error) (err error) {
	if storageErr == nil {
		return nil
	}

	defer func() {
		if rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.TokenRevocationStorage); rollBackTxnErr != nil {
			err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
		}
	}()

	if errors.Is(storageErr, fosite.ErrSerializationFailure) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithWrap(storageErr).
			WithHint("Failed to refresh token because of multiple concurrent requests using the same token. Please retry the request."))
	}

	if errors.Is(storageErr, fosite.ErrNotFound) || errors.Is(storageErr, fosite.ErrInactiveToken) {
		return errorsx.WithStack(fosite.ErrInvalidRequest.
			WithDebugf(storageErr.Error()).
			WithWrap(storageErr).
			WithHint("Failed to refresh token. Please retry the request."))
	}

	return errorsx.WithStack(fosite.ErrServerError.WithWrap(storageErr).WithDebug(storageErr.Error()))
}

func tokenFamilyRevoked(ctx context.Context, storage interface{}, requestID string) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	checker, ok := storage.(fosite.TokenFamilyRevocationChecker)
	if !ok {
		return false, nil
	}
	return checker.IsTokenFamilyRevoked(ctx, requestID)
}

func (c *RefreshTokenGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *RefreshTokenGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	return requester.GetGrantTypes().ExactOne("refresh_token")
}
