// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"strings"
	"time"

	"github.com/ory/x/errorsx"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		fosite.ScopeStrategyProvider
	}
	// Storage is optional. When set and it implements one of fosite's
	// revocation checker interfaces, the corresponding durable revocation
	// evidence is consulted before the token is reported active.
	Storage interface {
		GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	}
	// SignatureRevocationChecker is optional. When configured, a JWT whose
	// signature has a durable revocation marker is reported as inactive. The
	// marker is independent of the access token session, so the result stays
	// the same after a restart and for tokens that are not stored at all.
	SignatureRevocationChecker fosite.TokenSignatureRevocationChecker
	// TokenRevocationChecker is optional. It covers revocation evidence that
	// is keyed by the token digest rather than by the JWT signature.
	TokenRevocationChecker fosite.TokenRevocationChecker
}

// AccessTokenJWTToRequest tries to reconstruct fosite.Request from a JWT.
func AccessTokenJWTToRequest(token *jwt.Token) fosite.Requester {
	mapClaims := token.Claims
	claims := jwt.JWTClaims{}
	claims.FromMapClaims(mapClaims)

	requestedAt := claims.IssuedAt
	requestedAtClaim, ok := mapClaims["rat"]
	if ok {
		switch at := requestedAtClaim.(type) {
		case float64:
			requestedAt = time.Unix(int64(at), 0).UTC()
		case int64:
			requestedAt = time.Unix(at, 0).UTC()
		}
	}

	clientId := ""
	clientIdClaim, ok := mapClaims["client_id"]
	if ok {
		switch cid := clientIdClaim.(type) {
		case string:
			clientId = cid
		}
	}

	return &fosite.Request{
		RequestedAt: requestedAt,
		Client: &fosite.DefaultClient{
			ID: clientId,
		},
		// We do not really know which scopes were requested, so we set them to granted.
		RequestedScope: claims.Scope,
		GrantedScope:   claims.Scope,
		Session: &JWTSession{
			JWTClaims: &claims,
			JWTHeader: &jwt.Headers{
				Extra: token.Header,
			},
			ExpiresAt: map[fosite.TokenType]time.Time{
				fosite.AccessToken: claims.ExpiresAt,
			},
			Subject: claims.Subject,
		},
		// We do not really know which audiences were requested, so we set them to granted.
		RequestedAudience: claims.Audience,
		GrantedAudience:   claims.Audience,
	}
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse fosite.TokenUse, accessRequest fosite.AccessRequester, scopes []string) (fosite.TokenUse, error) {
	t, err := validate(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	signatureRevocationChecker := v.SignatureRevocationChecker
	if signatureRevocationChecker == nil {
		if checker, ok := v.Storage.(fosite.TokenSignatureRevocationChecker); ok {
			signatureRevocationChecker = checker
		}
	}
	if signatureRevocationChecker != nil {
		if signature := jwtTokenSignature(token); signature != "" {
			revoked, err := signatureRevocationChecker.IsTokenSignatureRevoked(ctx, signature)
			if err != nil {
				return "", errorsx.WithStack(err)
			}
			if revoked {
				return fosite.AccessToken, errorsx.WithStack(fosite.ErrInactiveToken.WithHint("The access token has been revoked."))
			}
		}
	}
	tokenRevocationChecker := v.TokenRevocationChecker
	if tokenRevocationChecker == nil {
		if checker, ok := v.Storage.(fosite.TokenRevocationChecker); ok {
			tokenRevocationChecker = checker
		}
	}
	if tokenRevocationChecker != nil {
		revoked, err := tokenRevocationChecker.IsTokenRevoked(ctx, fosite.TokenDigest(token))
		if err != nil {
			return "", errorsx.WithStack(err)
		}
		if revoked {
			return fosite.AccessToken, errorsx.WithStack(fosite.ErrInactiveToken.WithHint("The access token has been revoked."))
		}
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return fosite.AccessToken, err
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}

func jwtTokenSignature(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}
