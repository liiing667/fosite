// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite/storage"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

// HandleTokenEndpointRequest implements
// * https://tools.ietf.org/html/rfc6749#section-4.1.3 (everything)
func (c *AuthorizeExplicitGrantHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(errorsx.WithStack(fosite.ErrUnknownRequest))
	}

	if !request.GetClient().GetGrantTypes().Has("authorization_code") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use authorization grant \"authorization_code\"."))
	}

	code := request.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, request.GetSession())
	if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		if authorizeRequest == nil {
			return fosite.ErrServerError.
				WithHint("Misconfigured code lead to an error that prohibited the OAuth 2.0 Framework from processing this request.").
				WithDebug("GetAuthorizeCodeSession must return a value for \"fosite.Requester\" when returning \"ErrInvalidatedAuthorizeCode\".")
		}

		// Legacy code sessions keep the historical reuse response: revoke the
		// token family. New sessions carry a client-revision tombstone, so a
		// replay from an old client version fails closed without revoking the
		// single legitimate token generation.
		if shouldRevokeOnAuthorizeCodeReuse(authorizeRequest) && c.TokenRevocationStorage != nil {
			reqID := authorizeRequest.GetID()
			debug := ""
			if revErr := c.TokenRevocationStorage.RevokeAccessToken(ctx, reqID); revErr != nil {
				debug += "Revocation of access_token lead to error " + revErr.Error() + "."
			}
			if revErr := c.TokenRevocationStorage.RevokeRefreshToken(ctx, reqID); revErr != nil {
				debug += "Revocation of refresh_token lead to error " + revErr.Error() + "."
			}
			if debug != "" {
				reuseErr := authorizeCodeReuseError(request, authorizeRequest)
				reuseErr.HintField += " Additionally, an error occurred during token family revocation."
				reuseErr.DebugField += " " + debug
				return errorsx.WithStack(reuseErr)
			}
		}
		return errorsx.WithStack(authorizeCodeReuseError(request, authorizeRequest))
	} else if err != nil && errors.Is(err, fosite.ErrNotFound) {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageAuthorizeCodeLookup)
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageAuthorizeCodeLookup)
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	// The authorization server MUST verify that the authorization code is valid
	// This needs to happen after store retrieval for the session to be hydrated properly
	if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, request, code); err != nil {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageTokenValidation)
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithWrap(err).WithDebug(err.Error()))
	}

	// Override scopes
	request.SetRequestedScopes(authorizeRequest.GetRequestedScopes())

	// Override audiences
	request.SetRequestedAudience(authorizeRequest.GetRequestedAudience())

	// The authorization server MUST ensure that the authorization code was issued to the authenticated
	// confidential client, or if the client is public, ensure that the
	// code was issued to "client_id" in the request,
	if authorizeRequest.GetClient().GetID() != request.GetClient().GetID() {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageClientRevision)
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client ID from this request does not match the one from the authorize request."))
	}

	// The authenticated client must belong to the registration revision that
	// issued the code. A rotated registration may redeem the code only while it
	// still retains the old credential, and the resulting token is stamped with
	// the current revision.
	currentRevision, err := authorizeCodeClientRevision(ctx, c.CoreStorage, request, authorizeRequest)
	if err != nil {
		return errorsx.WithStack(err)
	}

	// ensure that the "redirect_uri" parameter is present if the
	// "redirect_uri" parameter was included in the initial authorization
	// request as described in Section 4.1.1, and if included ensure that
	// their values are identical.
	storedRevision := fosite.RequesterClientRevision(authorizeRequest)
	if err := validateAuthorizeCodeRedirect(request, authorizeRequest, storedRevision, currentRevision); err != nil {
		return errorsx.WithStack(err)
	}

	// Checking of POST client_id skipped, because:
	// If the client type is confidential or the client was issued client
	// credentials (or assigned other authentication requirements), the
	// client MUST authenticate with the authorization server as described
	// in Section 3.2.1.
	request.SetSession(authorizeRequest.GetSession())
	request.SetID(authorizeRequest.GetID())

	fosite.SetRequesterClientRevision(request, currentRevision)
	fosite.SetRequesterClientGeneration(request, fosite.ClientGeneration(request.GetClient()))
	fosite.SetRequesterRecoveryGeneration(request, fosite.RequesterRecoveryGeneration(authorizeRequest))
	fosite.SetRequesterAuthorizeCodeStatus(request, fosite.AuthorizeCodeStatusActive)
	fosite.SetRequesterAuthorizeCodeStage(request, fosite.RecoveryStageAuthorizeCodeActive)
	if redirectURI := authorizeCodeRedirectURI(authorizeRequest); redirectURI != "" {
		fosite.SetRequesterAuthorizationRedirectURI(request, redirectURI)
	}

	atLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	request.GetSession().SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(atLifespan).Round(time.Second))

	rtLifespan := fosite.GetEffectiveLifespan(request.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.RefreshToken, c.Config.GetRefreshTokenLifespan(ctx))
	if rtLifespan > -1 {
		request.GetSession().SetExpiresAt(fosite.RefreshToken, time.Now().UTC().Add(rtLifespan).Round(time.Second))
	}

	return nil
}

func canIssueRefreshToken(ctx context.Context, c *AuthorizeExplicitGrantHandler, request fosite.Requester) bool {
	scope := c.Config.GetRefreshTokenScopes(ctx)
	// Require one of the refresh token scopes, if set.
	if len(scope) > 0 && !request.GetGrantedScopes().HasOneOf(scope...) {
		return false
	}
	// Do not issue a refresh token to clients that cannot use the refresh token grant type.
	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return false
	}
	return true
}

func (c *AuthorizeExplicitGrantHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) (err error) {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	code := requester.GetRequestForm().Get("code")
	signature := c.AuthorizeCodeStrategy.AuthorizeCodeSignature(ctx, code)
	authorizeRequest, err := c.CoreStorage.GetAuthorizeCodeSession(ctx, signature, requester.GetSession())
	if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
		return errorsx.WithStack(authorizeCodeReuseError(requester, authorizeRequest))
	} else if err != nil && errors.Is(err, fosite.ErrNotFound) {
		fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageAuthorizeCodeLookup)
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err != nil {
		fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageAuthorizeCodeLookup)
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if err := c.AuthorizeCodeStrategy.ValidateAuthorizeCode(ctx, requester, code); err != nil {
		// This needs to happen after store retrieval for the session to be hydrated properly
		fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageTokenValidation)
		return errorsx.WithStack(fosite.ErrInvalidRequest.WithWrap(err).WithDebug(err.Error()))
	}

	// The code is bound to the client registration revision captured at
	// authorization time. A retired client version cannot mint a token from it.
	currentRevision, err := authorizeCodeClientRevision(ctx, c.CoreStorage, requester, authorizeRequest)
	if err != nil {
		return errorsx.WithStack(err)
	}
	storedRevision := fosite.RequesterClientRevision(authorizeRequest)
	if err := validateAuthorizeCodeRedirect(requester, authorizeRequest, storedRevision, currentRevision); err != nil {
		return errorsx.WithStack(err)
	}

	for _, scope := range authorizeRequest.GetGrantedScopes() {
		requester.GrantScope(scope)
	}

	for _, audience := range authorizeRequest.GetGrantedAudience() {
		requester.GrantAudience(audience)
	}

	// Prepare the generation and JWT/session claims before token generation so
	// JWT access tokens carry the same recovery metadata as stateful tokens.
	generation := prepareAuthorizeCodeRecoveryIdentity(requester, authorizeRequest, currentRevision)

	access, accessSignature, err := c.AccessTokenStrategy.GenerateAccessToken(ctx, requester)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	var refresh, refreshSignature string
	if canIssueRefreshToken(ctx, c, requester) {
		refresh, refreshSignature, err = c.RefreshTokenStrategy.GenerateRefreshToken(ctx, requester)
		if err != nil {
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	ctx, err = storage.MaybeBeginTx(ctx, c.CoreStorage)
	if err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}
	claimAttempted := false
	claimConflict := false
	claimed := false
	defer func() {
		if err != nil {
			rollBackTxnErr := storage.MaybeRollbackTx(ctx, c.CoreStorage)

			// If the code was claimed (or a claim was attempted) inside a
			// transaction that was rolled back, persist the tombstone outside
			// the transaction. A failed consumption or token creation must not
			// make the old client version redeemable again.
			if claimed || (claimAttempted && !claimConflict) {
				if consumer, ok := c.CoreStorage.(AuthorizeCodeConsumer); ok {
					_, _ = consumer.ConsumeAuthorizeCodeSession(
						fosite.WithClientRevision(context.Background(), currentRevision),
						signature,
						requester.GetSession(),
					)
				} else if tombstone, ok := c.CoreStorage.(AuthorizeCodeTombstoneStorage); ok {
					_ = tombstone.TombstoneAuthorizeCodeSession(
						fosite.WithClientRevision(context.Background(), currentRevision),
						signature,
						fosite.RecoveryStageTokenCreation,
					)
				}
			}

			if rollBackTxnErr != nil {
				err = errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebugf("error: %s; rollback error: %s", err, rollBackTxnErr))
			}
		}
	}()

	claimAttempted = true
	claimCtx := ctx
	if _, ok := c.CoreStorage.(AuthorizeCodeConsumer); ok {
		claimCtx = fosite.WithClientRevision(ctx, currentRevision)
	} else if _, ok := c.CoreStorage.(AuthorizeCodeTombstoneStorage); ok {
		claimCtx = fosite.WithClientRevision(ctx, currentRevision)
	}
	if err = c.CoreStorage.InvalidateAuthorizeCodeSession(
		claimCtx,
		signature,
	); err != nil {
		if errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) {
			claimConflict = true
			return errorsx.WithStack(authorizeCodeReuseError(requester, authorizeRequest))
		}
		if tombstone, ok := c.CoreStorage.(AuthorizeCodeTombstoneStorage); ok {
			_ = tombstone.TombstoneAuthorizeCodeSession(
				fosite.WithClientRevision(ctx, currentRevision),
				signature,
				fosite.RecoveryStageTokenCreation,
			)
		}
		fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageTokenCreation)
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else {
		claimed = true
	}

	generation = prepareAuthorizeCodeRecoveryMetadata(requester, authorizeRequest, currentRevision)

	if err = c.CoreStorage.CreateAccessTokenSession(ctx, accessSignature, requester.Sanitize([]string{})); err != nil {
		fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageTokenCreation)
		c.compensatePartialTokenCreation(ctx, accessSignature, "")
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	} else if refreshSignature != "" {
		if err = c.CoreStorage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, requester.Sanitize([]string{})); err != nil {
			fosite.SetRequesterRejectionStage(requester, fosite.RecoveryStageTokenCreation)
			c.compensatePartialTokenCreation(ctx, accessSignature, refreshSignature)
			return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
		}
	}

	responder.SetAccessToken(access)
	responder.SetTokenType("bearer")
	atLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeAuthorizationCode, fosite.AccessToken, c.Config.GetAccessTokenLifespan(ctx))
	responder.SetExpiresIn(getExpiresIn(requester, fosite.AccessToken, atLifespan, time.Now().UTC()))
	responder.SetScopes(requester.GetGrantedScopes())
	if refresh != "" {
		responder.SetExtra("refresh_token", refresh)
	}
	setAuthorizeCodeRecoveryExtras(responder, currentRevision, fosite.RequesterClientGeneration(requester), generation)

	if err = storage.MaybeCommitTx(ctx, c.CoreStorage); err != nil {
		return errorsx.WithStack(fosite.ErrServerError.WithWrap(err).WithDebug(err.Error()))
	}

	return nil
}

// compensatePartialTokenCreation removes token sessions that were written
// before a later part of the same exchange failed. Transactional stores roll
// back on their own; non-transactional stores still must not leave a token
// half-generation behind.
func (c *AuthorizeExplicitGrantHandler) compensatePartialTokenCreation(ctx context.Context, accessSignature, refreshSignature string) {
	if _, transactional := c.CoreStorage.(storage.Transactional); transactional {
		return
	}
	_, canConsume := c.CoreStorage.(AuthorizeCodeConsumer)
	_, canTombstone := c.CoreStorage.(AuthorizeCodeTombstoneStorage)
	if !canConsume && !canTombstone {
		return
	}
	if accessSignature != "" {
		_ = c.CoreStorage.DeleteAccessTokenSession(ctx, accessSignature)
	}
	if refreshSignature != "" {
		_ = c.CoreStorage.DeleteRefreshTokenSession(ctx, refreshSignature)
	}
}

func setAuthorizeCodeRecoveryExtras(responder fosite.AccessResponder, clientRevision string, clientGeneration, generation uint64) {
	if clientRevision != "" {
		responder.SetExtra("client_version", clientRevision)
		responder.SetExtra("client_revision", clientRevision)
		responder.SetExtra("client_authentication_version", clientRevision)
		if clientGeneration == 0 {
			clientGeneration = fosite.ClientRevisionGeneration(clientRevision)
		}
		responder.SetExtra("client_generation", clientGeneration)
	}
	if generation != 0 {
		responder.SetExtra("recovery_generation", generation)
		responder.SetExtra("generation", generation)
		responder.SetExtra("authorization_generation", generation)
	}
	responder.SetExtra("authorization_code_status", fosite.AuthorizeCodeStatusConsumed)
	responder.SetExtra("code_status", fosite.AuthorizeCodeStatusConsumed)
	responder.SetExtra("authorization_code_consumed", true)
	responder.SetExtra("code_consumed", true)
	responder.SetExtra("recovery_stage", fosite.RecoveryStageAuthorizeCodeConsumed)
}

func (c *AuthorizeExplicitGrantHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *AuthorizeExplicitGrantHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "authorization_code"
	return requester.GetGrantTypes().ExactOne("authorization_code")
}
