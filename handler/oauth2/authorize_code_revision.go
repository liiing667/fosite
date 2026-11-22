// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"fmt"

	"github.com/ory/fosite"
)

type authorizeCodeClientManager interface {
	GetClient(ctx context.Context, id string) (fosite.Client, error)
}

// authorizeCodeClientRevision checks that the authenticated client belongs to
// the client-registration revision frozen in the authorization-code session.
// Legacy code sessions without revision metadata keep the historical behavior
// and are upgraded on first use.
func authorizeCodeClientRevision(ctx context.Context, storage interface{}, request fosite.AccessRequester, authorizeRequest fosite.Requester) (string, error) {
	if request.GetClient() == nil {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageClientRevision)
		return "", fosite.ErrInvalidGrant.
			WithHint("The OAuth 2.0 Client could not be resolved for this authorization code exchange.").
			WithDebug("stage=" + fosite.RecoveryStageClientRevision + "; token_client_revision=<missing>")
	}

	fosite.SetRequesterRejectionStage(request, "")
	currentRevision := fosite.ClientRevision(request.GetClient())

	// When the core storage also owns clients, reject a request that carries a
	// stale client object even if it still knows the old secret. The real
	// authentication path resolves the current registration, so this is a
	// strict comparison, not a rotation-lineage check.
	if clientManager, ok := storage.(authorizeCodeClientManager); ok {
		if registeredClient, err := clientManager.GetClient(ctx, request.GetClient().GetID()); err == nil && registeredClient != nil {
			registeredRevision := fosite.ClientRevision(registeredClient)
			if registeredRevision != currentRevision {
				fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageClientRevision)
				return "", fosite.ErrInvalidGrant.
					WithHint("The OAuth 2.0 Client authentication version does not match the currently registered client version.").
					WithDebug(fmt.Sprintf("stage=%s; registered_client_revision=%s; token_client_revision=%s",
						fosite.RecoveryStageClientRevision, registeredRevision, currentRevision))
			}
		}
	}

	storedRevision := fosite.RequesterClientRevision(authorizeRequest)
	if storedRevision == "" {
		return currentRevision, nil
	}
	if storedRevision == currentRevision {
		return currentRevision, nil
	}
	if fosite.ClientRevisionCompatibleWithRequest(authorizeRequest, request.GetClient()) {
		// Client-secret rotation: the current registration still retains the
		// credential that issued the code. The token is stamped with the
		// current revision so it never appears to belong to a superseded
		// registration.
		return currentRevision, nil
	}

	fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageClientRevision)
	return "", fosite.ErrInvalidGrant.
		WithHint("The OAuth 2.0 Client authentication version does not match the version that initiated the authorization request.").
		WithDebug(fmt.Sprintf("stage=%s; authorize_client_revision=%s; token_client_revision=%s",
			fosite.RecoveryStageClientRevision, storedRevision, currentRevision))
}

func authorizeCodeRedirectURI(authorizeRequest fosite.Requester) string {
	if redirectURI := fosite.RequesterAuthorizationRedirectURI(authorizeRequest); redirectURI != "" {
		return redirectURI
	}
	return authorizeRequest.GetRequestForm().Get("redirect_uri")
}

// validateAuthorizeCodeRedirect preserves the existing OAuth redirect
// semantics: when the authorization request contained a redirect_uri, the
// token request must repeat exactly the same value. If the client
// registration changed meanwhile, the frozen redirect must still be allowed by
// the current registration.
func validateAuthorizeCodeRedirect(request fosite.AccessRequester, authorizeRequest fosite.Requester, storedRevision, currentRevision string) error {
	forcedRedirectURI := authorizeCodeRedirectURI(authorizeRequest)
	if forcedRedirectURI == "" {
		return nil
	}

	actualRedirectURI := request.GetRequestForm().Get("redirect_uri")
	if actualRedirectURI != forcedRedirectURI {
		fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageRedirectURI)
		return fosite.ErrInvalidGrant.
			WithHint("The \"redirect_uri\" from this request does not match the one from the authorize request.").
			WithDebug(fmt.Sprintf("stage=%s; authorize_redirect_uri=%s; token_redirect_uri=%s",
				fosite.RecoveryStageRedirectURI, forcedRedirectURI, actualRedirectURI))
	}

	if storedRevision != "" && currentRevision != "" && storedRevision != currentRevision && request.GetClient() != nil {
		if _, err := fosite.MatchRedirectURIWithClientRedirectURIs(forcedRedirectURI, request.GetClient()); err != nil {
			fosite.SetRequesterRejectionStage(request, fosite.RecoveryStageRedirectURI)
			return fosite.ErrInvalidGrant.
				WithHint("The redirect URI from the authorize request is no longer registered for the current OAuth 2.0 Client.").
				WithWrap(err).
				WithDebug(fmt.Sprintf("stage=%s; redirect_uri=%s; client_revision=%s",
					fosite.RecoveryStageRedirectURI, forcedRedirectURI, currentRevision))
		}
	}

	return nil
}

// prepareAuthorizeCodeRecoveryIdentity copies the frozen generation and
// revision onto the token requester and its session before token generation.
func prepareAuthorizeCodeRecoveryIdentity(request fosite.AccessRequester, authorizeRequest fosite.Requester, currentRevision string) uint64 {
	generation := fosite.RequesterRecoveryGeneration(authorizeRequest)
	if generation == 0 {
		generation = fosite.EnsureRecoveryGeneration(request)
	} else {
		fosite.SetRequesterRecoveryGeneration(request, generation)
	}

	fosite.SetRequesterClientRevision(request, currentRevision)
	if request.GetClient() != nil {
		fosite.SetRequesterClientGeneration(request, fosite.ClientGeneration(request.GetClient()))
	}
	if redirectURI := authorizeCodeRedirectURI(authorizeRequest); redirectURI != "" {
		fosite.SetRequesterAuthorizationRedirectURI(request, redirectURI)
	}
	setAuthorizeCodeRecoverySessionClaims(request, currentRevision, fosite.RequesterClientGeneration(request), generation)
	return generation
}

// prepareAuthorizeCodeRecoveryMetadata additionally marks the code as consumed
// on the requester after the one-time claim succeeded.
func prepareAuthorizeCodeRecoveryMetadata(request fosite.AccessRequester, authorizeRequest fosite.Requester, currentRevision string) uint64 {
	generation := prepareAuthorizeCodeRecoveryIdentity(request, authorizeRequest, currentRevision)
	fosite.SetRequesterAuthorizeCodeStatus(request, fosite.AuthorizeCodeStatusConsumed)
	fosite.SetRequesterAuthorizeCodeStage(request, fosite.RecoveryStageAuthorizeCodeConsumed)
	fosite.SetRequesterRejectionStage(request, "")
	return generation
}

// authorizeCodeReuseError describes a replayed or already-consumed code. The
// stage distinguishes a concurrent claim by another client version from an
// ordinary duplicate submission.
func authorizeCodeReuseError(request fosite.AccessRequester, authorizeRequest fosite.Requester) *fosite.RFC6749Error {
	storedRevision := fosite.RequesterClientRevision(authorizeRequest)
	currentRevision := ""
	if request.GetClient() != nil {
		currentRevision = fosite.ClientRevision(request.GetClient())
	}

	stage := fosite.RecoveryStageAuthorizeCodeConsumed
	if storedRevision != "" && currentRevision != "" &&
		storedRevision != currentRevision &&
		!fosite.ClientRevisionCompatibleWithRequest(authorizeRequest, request.GetClient()) {
		stage = fosite.RecoveryStageClientRevision
	}
	fosite.SetRequesterRejectionStage(request, stage)

	return fosite.ErrInvalidGrant.
		WithHint("The authorization code has already been used.").
		WithDebug(fmt.Sprintf("stage=%s; code_status=%s; authorize_client_revision=%s; token_client_revision=%s",
			stage, fosite.RequesterAuthorizeCodeStatus(authorizeRequest), storedRevision, currentRevision))
}

// shouldRevokeOnAuthorizeCodeReuse keeps the historical replay response for
// legacy code sessions that have no client-revision tombstone. New code
// sessions fail closed with invalid_grant but do not let a replay revoke the
// single legitimate token generation.
func shouldRevokeOnAuthorizeCodeReuse(authorizeRequest fosite.Requester) bool {
	return fosite.RequesterClientRevision(authorizeRequest) == ""
}
