// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package openid

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ory/x/errorsx"

	"github.com/pkg/errors"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type OpenIDConnectRefreshHandler struct {
	*IDTokenHandleHelper

	Config interface {
		fosite.IDTokenLifespanProvider
	}
}

var (
	_ Session           = (*refreshTokenSession)(nil)
	_ Session           = (*refreshTokenClaimsSession)(nil)
	_ fosite.Requester  = (*refreshTokenRequester)(nil)
)

func (c *OpenIDConnectRefreshHandler) HandleTokenEndpointRequest(ctx context.Context, request fosite.AccessRequester) error {
	if !c.CanHandleTokenEndpointRequest(ctx, request) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !request.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(fosite.ErrUnauthorizedClient.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"refresh_token\"."))
	}

	// Refresh tokens can only be issued by an authorize_code which in turn disables the need to check if the id_token
	// response type is enabled by the client.
	//
	// if !request.GetClient().GetResponseTypes().Has("id_token") {
	// 	return errorsx.WithStack(fosite.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := request.GetSession().(Session)
	if !ok {
		return errors.New("Failed to generate id token because session must be of type fosite/handler/openid.Session")
	}

	// Freeze every claim that identifies the authorization (nonce, auth_time,
	// subject, acr/amr, ...) into a single immutable snapshot for this refresh
	// generation. The snapshot is derived once from the hydrated session and is
	// never mutated again, so a concurrently or out-of-order completing
	// response can not mix claims of different refresh generations into one ID
	// token (for example a fresh at_hash with a stale nonce/auth_time).
	generation := newRefreshGeneration(sess.IDTokenClaims())

	// Carry the generation alongside the working session. Volatile
	// per-generation values (jti, at_hash, exp, iat) are only ever written to
	// private copies in PopulateTokenEndpointResponse, so a retry rebuilds the
	// exact same generation instead of accumulating two independently
	// verifiable ID tokens. The session persisted by the storage layer is the
	// original openid session, so restarts hydrate the same snapshot again.
	request.SetSession(&refreshTokenSession{Session: sess, generation: generation})

	return nil
}

func (c *OpenIDConnectRefreshHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	if !c.CanHandleTokenEndpointRequest(ctx, requester) {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetGrantedScopes().Has("openid") {
		return errorsx.WithStack(fosite.ErrUnknownRequest)
	}

	if !requester.GetClient().GetGrantTypes().Has("refresh_token") {
		return errorsx.WithStack(fosite.ErrInvalidGrant.WithHint("The OAuth 2.0 Client is not allowed to use the authorization grant \"refresh_token\"."))
	}

	// Disabled because this is already handled at the authorize_request_handler
	// if !requester.GetClient().GetResponseTypes().Has("id_token") {
	// 	 return errorsx.WithStack(fosite.ErrUnknownRequest.WithDebug("The client is not allowed to use response type id_token"))
	// }

	sess, ok := requester.GetSession().(Session)
	if !ok {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because session must be of type fosite/handler/openid.Session."))
	}

	generation, sess := refreshGenerationFromSession(sess)
	if generation == nil {
		if sess == nil {
			return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because session must be of type fosite/handler/openid.Session."))
		}
		// HandleTokenEndpointRequest did not run (for example when the handler
		// is invoked directly). Rebuild a generation from the current claims so
		// that the behavior degrades gracefully.
		generation = newRefreshGeneration(sess.IDTokenClaims())
	}

	if generation.claims.Subject == "" {
		return errorsx.WithStack(fosite.ErrServerError.WithDebug("Failed to generate id token because subject is an empty string."))
	}

	// Assemble this generation's claims on a private copy: the at_hash is
	// derived exclusively from this generation's access token and combined only
	// with the frozen nonce/auth_time snapshot. The stored session is never
	// touched, so another request can not observe a half-written hash.
	claims := *generation.claims
	// Copy reference types as well so that strategy-side bookkeeping (for
	// example appending the audience) can never reach the immutable snapshot.
	claims.Audience = append([]string(nil), generation.claims.Audience...)
	claims.AuthenticationMethodsReferences = append([]string(nil), generation.claims.AuthenticationMethodsReferences...)
	if generation.claims.Extra != nil {
		claims.Extra = make(map[string]interface{}, len(generation.claims.Extra))
		for key, value := range generation.claims.Extra {
			claims.Extra[key] = value
		}
	}
	claims.AccessTokenHash = c.GetAccessTokenHash(ctx, requester, responder)
	claims.JTI = generation.jti
	claims.CodeHash = ""
	claims.IssuedAt = time.Now().Truncate(time.Second)
	claims.ExpiresAt = time.Time{}

	idTokenLifespan := fosite.GetEffectiveLifespan(requester.GetClient(), fosite.GrantTypeRefreshToken, fosite.IDToken, c.Config.GetIDTokenLifespan(ctx))
	return c.IssueExplicitIDToken(ctx, idTokenLifespan, &refreshTokenRequester{
		AccessRequester: requester,
		session: &refreshTokenClaimsSession{
			Session: sess,
			claims:  &claims,
		},
	}, responder)
}

func (c *OpenIDConnectRefreshHandler) CanSkipClientAuth(ctx context.Context, requester fosite.AccessRequester) bool {
	return false
}

func (c *OpenIDConnectRefreshHandler) CanHandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) bool {
	// grant_type REQUIRED.
	// Value MUST be set to "refresh_token"
	return requester.GetGrantTypes().ExactOne("refresh_token")
}

// refreshGeneration bundles the immutable identity claims of a single refresh
// generation together with the stable ID token identifier (jti) for that
// generation.
type refreshGeneration struct {
	// jti uniquely identifies the ID token of this generation. It is generated
	// once and is never regenerated while the generation is being served, so
	// retries do not produce a second verifiable ID token.
	jti string
	// claims is the immutable snapshot of all claims carried over from the
	// authorization session. Nothing in here is ever mutated in place.
	claims *jwt.IDTokenClaims
}

// newRefreshGeneration snapshots the supplied claims into a new, immutable
// generation. Volatile per-token values are cleared because they are recomputed
// for every generation while identity claims such as the nonce or auth_time
// are preserved verbatim. Sessions without a nonce simply keep the empty
// nonce, which preserves the historical claim semantics.
func newRefreshGeneration(claims *jwt.IDTokenClaims) *refreshGeneration {
	snapshot := *claims
	snapshot.JTI = ""
	snapshot.AccessTokenHash = ""
	snapshot.CodeHash = ""
	snapshot.ExpiresAt = time.Time{}
	// Detach the reference types so mutations of the caller's claims can never
	// bleed into this generation (and vice versa).
	snapshot.Audience = append([]string(nil), claims.Audience...)
	snapshot.AuthenticationMethodsReferences = append([]string(nil), claims.AuthenticationMethodsReferences...)
	if claims.Extra != nil {
		snapshot.Extra = make(map[string]interface{}, len(claims.Extra))
		for key, value := range claims.Extra {
			snapshot.Extra[key] = value
		}
	}

	return &refreshGeneration{
		jti:    uuid.New().String(),
		claims: &snapshot,
	}
}

// refreshTokenSession carries the generation alongside the working session
// without modifying the session that gets persisted by the storage layer.
type refreshTokenSession struct {
	Session
	generation *refreshGeneration
}

func refreshGenerationFromSession(session fosite.Session) (*refreshGeneration, Session) {
	generationSession, ok := session.(*refreshTokenSession)
	if !ok {
		openIDSession, _ := session.(Session)
		return nil, openIDSession
	}
	return generationSession.generation, generationSession.Session
}

// refreshTokenRequester exposes the generation-specific claims through the
// regular Requester interface while leaving the original requester and its
// persisted session untouched.
type refreshTokenRequester struct {
	fosite.AccessRequester
	session fosite.Session
}

func (r *refreshTokenRequester) GetSession() fosite.Session {
	return r.session
}

type refreshTokenClaimsSession struct {
	Session
	claims *jwt.IDTokenClaims
}

func (s *refreshTokenClaimsSession) IDTokenClaims() *jwt.IDTokenClaims {
	return s.claims
}

func (s *refreshTokenClaimsSession) Clone() fosite.Session {
	return &refreshTokenClaimsSession{
		Session: s.Session.Clone().(Session),
		claims:  s.claims,
	}
}
