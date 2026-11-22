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

	// Pin the token family, the client, and the generation (the signature of the
	// presented refresh token) of this refresh request as candidates. All
	// subsequent steps - including the token rotation in
	// PopulateTokenEndpointResponse - operate on exactly these pinned values, so
	// that the refresh token family keeps exactly one valid generation, even when
	// a rotation fails halfway through, tokens are used concurrently, or the
	// server was restarted in between.
	pinnedTokenFamily := originalRequest.GetID()
	pinnedClientID := originalRequest.GetClient().GetID()

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
	if pinnedClientID != request.GetClient().GetID() {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the ID during the initial token issuance."))
	}

	request.SetID(pinnedTokenFamily)
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

	ctx, err = storage.MaybeBeginTx(ctx, c.TokenRevocationStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	storeReq := requester.Sanitize([]string{})
	storeReq.SetID(requester.GetID())

	// Rotate out exactly the pinned generation (signature) of the pinned token
	// family (requester.GetID()) that was determined in
	// HandleTokenEndpointRequest. If the presented generation was already
	// rotated - e.g. by a concurrent request - the storage returns an error and
	// no new tokens are issued, leaving the family with exactly one valid
	// generation.
	if err = c.TokenRevocationStorage.RotateRefreshToken(ctx, requester.GetID(), signature); err != nil {
		return c.handleRefreshTokenEndpointStorageError(ctx, err)
	}

	if err = c.TokenRevocationStorage.CreateAccessTokenSession(ctx, accessSignature, storeReq); err != nil {
		return c.handleRefreshTokenEndpointStorageError(ctx, err)
	}

	if err = c.TokenRevocationStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, storeReq); err != nil {
		return c.handleRefreshTokenEndpointStorageError(ctx, err)
	}

	responder.SetAccessToken(accessToken)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeRefreshToken, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	responder.SetExtra("refresh_token", refreshToken)

	if err = storage.MaybeCommitTx(ctx, c.TokenRevocationStorage); err != nil {
		return c.handleRefreshTokenEndpointStorageError(ctx, err)
	}

	return nil
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

	// The whole token family is revoked best-effort: a storage error in one of
	// the calls must not abort the revocation halfway through and keep the
	// remaining - possibly stolen - tokens of the family alive. The first
	// unexpected error is returned (and rolled back) after all calls were
	// attempted.
	var revocationErr error
	tryRevoke := func(revoke func(ctx context.Context) error) {
		if revokeErr := revoke(ctx); revokeErr != nil && !errors.Is(revokeErr, fosite.ErrNotFound) && revocationErr == nil {
			revocationErr = revokeErr
		}
	}

	tryRevoke(func(ctx context.Context) error {
		return c.TokenRevocationStorage.DeleteRefreshTokenSession(ctx, signature)
	})
	tryRevoke(func(ctx context.Context) error {
		return c.TokenRevocationStorage.RevokeRefreshToken(ctx, req.GetID())
	})
	tryRevoke(func(ctx context.Context) error {
		return c.TokenRevocationStorage.RevokeAccessToken(ctx, req.GetID())
	})

	if err = revocationErr; err != nil {
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

func (c *RefreshTokenGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *RefreshTokenGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token".
	return requester.GetGrantTypes().ExactOne("refresh_token")
}
