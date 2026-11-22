// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

type StatelessJWTValidator struct {
	jwt.Signer
	Config interface {
		fosite.ScopeStrategyProvider
	}
	// TokenRevocationChecker and AccessTokenStrategy are optional. When both
	// are set, a revoked access-token signature is rejected even though the
	// JWT itself does not require a stored session.
	TokenRevocationChecker fosite.TokenSignatureRevocationChecker
	AccessTokenStrategy    AccessTokenStrategy
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

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if v.TokenRevocationChecker != nil && v.AccessTokenStrategy != nil {
		signature := v.AccessTokenStrategy.AccessTokenSignature(ctx, token)
		revoked, err := v.TokenRevocationChecker.IsTokenSignatureRevoked(ctx, signature)
		if err != nil {
			return "", err
		}
		if revoked {
			return "", fosite.ErrRequestUnauthorized.
				WithWrap(fosite.ErrInactiveToken).
				WithHint("The token signature has been revoked.")
		}
	}

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return fosite.AccessToken, err
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}
