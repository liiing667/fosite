// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

type TokenRevocationHandler struct {
	TokenRevocationStorage TokenRevocationStorage
	RefreshTokenStrategy   RefreshTokenStrategy
	AccessTokenStrategy    AccessTokenStrategy
}

// RevokeToken implements https://tools.ietf.org/html/rfc7009#section-2.1
// The token type hint indicates which token type check should be performed first.
func (r *TokenRevocationHandler) RevokeToken(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) error {
	_, err := r.RevokeTokenWithReport(ctx, token, tokenType, client)
	return err
}

// RevokeTokenWithReport behaves like RevokeToken but additionally returns the
// token family, token type and failure stage determined while processing the
// request. The report never changes the RFC 7009 response or error code.
func (r *TokenRevocationHandler) RevokeTokenWithReport(ctx context.Context, token string, tokenType fosite.TokenType, client fosite.Client) (fosite.TokenStatusReport, error) {
	report := fosite.TokenStatusReport{
		TokenDigest: fosite.TokenDigest(token),
		TokenType:   tokenType,
		TokenUse:    tokenType,
		Stage:       fosite.TokenStatusStageRevocation,
	}

	type discoveryResult struct {
		request   fosite.Requester
		tokenUse  fosite.TokenUse
		signature string
		err       error
	}
	discoveryFuncs := []func() discoveryResult{
		func() (result discoveryResult) {
			// Refresh token
			result.tokenUse = fosite.RefreshToken
			result.signature = r.RefreshTokenStrategy.RefreshTokenSignature(ctx, token)
			result.request, result.err = r.TokenRevocationStorage.GetRefreshTokenSession(ctx, result.signature, nil)
			return result
		},
		func() (result discoveryResult) {
			// Access token
			result.tokenUse = fosite.AccessToken
			result.signature = r.AccessTokenStrategy.AccessTokenSignature(ctx, token)
			result.request, result.err = r.TokenRevocationStorage.GetAccessTokenSession(ctx, result.signature, nil)
			return result
		},
	}

	// Token type hinting
	if tokenType == fosite.AccessToken {
		discoveryFuncs[0], discoveryFuncs[1] = discoveryFuncs[1], discoveryFuncs[0]
	}

	discovered := []discoveryResult{discoveryFuncs[0]()}
	if discovered[0].err != nil {
		discovered = append(discovered, discoveryFuncs[1]())
	}

	var ar fosite.Requester
	var matchedTokenUse fosite.TokenUse
	var matchedSignature string
	var requestID string
	var familyClientID string
	var firstDiscoveryErr, secondDiscoveryErr error
	for _, result := range discovered {
		if result.err == nil {
			ar = result.request
			matchedTokenUse = result.tokenUse
			matchedSignature = result.signature
			break
		}
	}
	if ar == nil {
		for _, result := range discovered {
			if result.request != nil {
				ar = result.request
				matchedTokenUse = result.tokenUse
				matchedSignature = result.signature
				break
			}
		}
	}
	if len(discovered) > 0 {
		firstDiscoveryErr = discovered[0].err
	}
	if len(discovered) > 1 {
		secondDiscoveryErr = discovered[1].err
	} else {
		secondDiscoveryErr = nil
	}

	if ar != nil {
		if arClient := ar.GetClient(); arClient != nil {
			familyClientID = arClient.GetID()
		}
	} else {
		// The token session may have been removed by a concurrent refresh
		// between issuance and revocation. Resolve the family from the token
		// signature so the revocation still reaches the current generation.
		var resolveFailure error
		if resolver, ok := r.TokenRevocationStorage.(fosite.TokenFamilyResolver); ok {
			for _, result := range discovered {
				if result.signature == "" {
					continue
				}
				resolution, resolveErr := resolver.ResolveTokenFamily(ctx, result.tokenUse, result.signature)
				if resolveErr != nil {
					if !errors.Is(resolveErr, fosite.ErrNotFound) && resolveFailure == nil {
						resolveFailure = resolveErr
					}
					continue
				}
				if resolution.RequestID == "" {
					continue
				}
				requestID = resolution.RequestID
				familyClientID = resolution.ClientID
				matchedTokenUse = result.tokenUse
				matchedSignature = result.signature
				break
			}
		}
		if requestID == "" && resolveFailure != nil {
			report.FailureLocation = fosite.TokenStatusStageStorage
			report.Error = resolveFailure.Error()
			return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
		}
	}

	if familyClientID != "" && familyClientID != client.GetID() {
		report.FailureLocation = fosite.TokenStatusStageAuthentication
		report.Error = fosite.ErrUnauthorizedClient.Error()
		return report, errorsx.WithStack(fosite.ErrUnauthorizedClient)
	}

	if ar != nil {
		requestID = ar.GetID()
	}

	if requestID != "" && firstDiscoveryErr != nil && secondDiscoveryErr != nil {
		revoked, checkErr := tokenFamilyRevoked(ctx, r.TokenRevocationStorage, requestID)
		if checkErr != nil {
			report.FailureLocation = fosite.TokenStatusStageStorage
			report.Error = checkErr.Error()
			return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
		}
		if revoked {
			report.RequestID = requestID
			report.RequestFamily = requestID
			report.ClientID = client.GetID()
			report.TokenUse = matchedTokenUse
			report.TokenType = matchedTokenUse
			report.TokenSignature = matchedSignature
			report.Revoked = true
			report.Stage = fosite.TokenStatusStageRevoked
			r.populateFamilyReport(ctx, &report)
			return report, nil
		}
	}

	if requestID == "" && ar == nil {
		// Both "not found" and "inactive" mean that the token is already gone.
		// This is the RFC 7009 idempotent success path.
		discoveryErr := storeErrorsToRevocationError(firstDiscoveryErr, secondDiscoveryErr)
		if discoveryErr != nil {
			report.FailureLocation = fosite.TokenStatusStageStorage
			report.Error = discoveryErr.Error()
			return report, discoveryErr
		}
		report.Revoked = true
		report.Stage = fosite.TokenStatusStageRevoked
		return report, nil
	}

	report.RequestID = requestID
	report.RequestFamily = requestID
	report.ClientID = client.GetID()
	report.TokenUse = matchedTokenUse
	report.TokenType = matchedTokenUse
	report.TokenSignature = matchedSignature

	var err1, err2 error

	txCtx, err := storage.MaybeBeginTx(ctx, r.TokenRevocationStorage)
	if err != nil {
		report.FailureLocation = fosite.TokenStatusStageStorage
		report.Error = err.Error()
		return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
	}

	rollback := true
	defer func() {
		if rollback {
			_ = storage.MaybeRollbackTx(txCtx, r.TokenRevocationStorage)
		}
	}()

	// Prefer the atomic family operation when the storage supports it. This
	// writes the tombstone before any token-session cleanup, so an error in a
	// later step can never expose a half-revoked family.
	familyHandled := false
	if requestID != "" {
		if checker, ok := r.TokenRevocationStorage.(fosite.TokenFamilyRevocationChecker); ok {
			revoked, checkErr := checker.IsTokenFamilyRevoked(txCtx, requestID)
			if checkErr != nil {
				report.FailureLocation = fosite.TokenStatusStageStorage
				report.Error = checkErr.Error()
				return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
			}
			familyHandled = revoked
		}
		if !familyHandled {
			if revoker, ok := r.TokenRevocationStorage.(fosite.TokenFamilyRevoker); ok {
				if revokeErr := revoker.RevokeTokenFamily(txCtx, requestID); revokeErr == nil {
					familyHandled = true
				} else if !errors.Is(revokeErr, fosite.ErrNotFound) && !errors.Is(revokeErr, fosite.ErrInactiveToken) {
					report.FailureLocation = fosite.TokenStatusStageStorage
					report.Error = revokeErr.Error()
					return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
				}
			}
		}
	}

	// Keep the RFC 7009 error contract: both legacy storage operations are
	// attempted even if the first one fails, and a failure is reported as
	// ErrTemporarilyUnavailable. On stores with a family tombstone the first
	// successful step is already sufficient to make every consumer fail
	// closed; on transactional stores the deferred rollback restores the
	// complete old family instead.
	err1 = r.TokenRevocationStorage.RevokeRefreshToken(txCtx, requestID)
	err2 = r.TokenRevocationStorage.RevokeAccessToken(txCtx, requestID)

	// If neither legacy operation established the family tombstone (for
	// example because the storage only exposes the optional family API), write
	// it now. This also repairs a store whose cleanup step failed halfway.
	var familyErr error
	if !familyHandled {
		familyErr = r.ensureTokenFamilyRevoked(txCtx, requestID)
	}

	if err := storeErrorsToRevocationError(err1, err2); err != nil {
		report.FailureLocation = fosite.TokenStatusStageStorage
		report.Error = err.Error()
		return report, err
	}
	if familyErr != nil {
		report.FailureLocation = fosite.TokenStatusStageStorage
		report.Error = familyErr.Error()
		return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
	}

	if err := storage.MaybeCommitTx(txCtx, r.TokenRevocationStorage); err != nil {
		report.FailureLocation = fosite.TokenStatusStageStorage
		report.Error = err.Error()
		_ = storage.MaybeRollbackTx(txCtx, r.TokenRevocationStorage)
		return report, errorsx.WithStack(fosite.ErrTemporarilyUnavailable)
	}
	rollback = false

	report.Active = false
	report.Revoked = true
	report.Stage = fosite.TokenStatusStageRevoked
	report.RevokedAt = time.Now().UTC()

	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenFamilyRevocationRecorder); ok && report.RequestID != "" {
		_ = recorder.RecordTokenFamilyRevocation(ctx, fosite.TokenFamilyRevocationRecord{
			RequestID:      report.RequestID,
			ClientID:       report.ClientID,
			TokenType:      report.TokenType,
			TokenUse:       report.TokenUse,
			TokenSignature: report.TokenSignature,
			RevokedAt:      report.RevokedAt,
			ExpiresAt:      revocationExpiry(ar, report.TokenUse),
			Source:         "token-revocation-handler",
			Stage:          report.Stage,
		})
	}
	r.populateFamilyReport(ctx, &report)

	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenRevocationRecorder); ok {
		_ = recorder.RecordTokenRevocation(ctx, fosite.TokenRevocationRecord{
			TokenDigest:          report.TokenDigest,
			TokenSignature:       report.TokenSignature,
			ClientID:             report.ClientID,
			TokenUse:             report.TokenUse,
			TokenType:            report.TokenType,
			RequestID:            report.RequestID,
			RequestFamily:        report.RequestFamily,
			RevokedAt:            report.RevokedAt,
			ExpiresAt:            revocationExpiry(ar, report.TokenUse),
			Generation:           report.Generation,
			RevocationGeneration: report.RevocationGeneration,
			Source:               "token-revocation-handler",
			Stage:                report.Stage,
		})
	}
	if recorder, ok := r.TokenRevocationStorage.(fosite.TokenSignatureRevocationRecorder); ok {
		_ = recorder.RecordTokenSignatureRevocation(ctx, matchedSignature, revocationExpiry(ar, report.TokenUse))
	}

	return report, nil
}

func (r *TokenRevocationHandler) ensureTokenFamilyRevoked(ctx context.Context, requestID string) error {
	if requestID == "" {
		return nil
	}

	checker, hasChecker := r.TokenRevocationStorage.(fosite.TokenFamilyRevocationChecker)
	if hasChecker {
		revoked, err := checker.IsTokenFamilyRevoked(ctx, requestID)
		if err != nil {
			return err
		}
		if revoked {
			return nil
		}
	}

	revoker, ok := r.TokenRevocationStorage.(fosite.TokenFamilyRevoker)
	if !ok {
		return nil
	}
	err := revoker.RevokeTokenFamily(ctx, requestID)
	if errors.Is(err, fosite.ErrNotFound) || errors.Is(err, fosite.ErrInactiveToken) {
		return nil
	}
	return err
}

func (r *TokenRevocationHandler) populateFamilyReport(ctx context.Context, report *fosite.TokenStatusReport) {
	provider, ok := r.TokenRevocationStorage.(fosite.TokenFamilyRevocationStateProvider)
	if !ok || report.RequestID == "" {
		return
	}
	record, err := provider.GetTokenFamilyRevocation(ctx, report.RequestID)
	if err != nil {
		return
	}
	report.Generation = record.Generation
	report.RevocationGeneration = record.Generation
	report.RevokedAt = record.RevokedAt
	if report.TokenType == "" {
		report.TokenType = record.TokenType
		report.TokenUse = record.TokenUse
	}
	if report.StatusSource == "" {
		report.StatusSource = record.Source
	}
	if report.StatusSource == "" {
		report.StatusSource = "token-revocation-handler"
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
