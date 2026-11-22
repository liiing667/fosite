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

	request := &fosite.Request{
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

	if revision := jwtStringClaim(mapClaims, "client_revision", "client_version", "client_authentication_version"); revision != "" {
		request.SetClientRevision(revision)
	}
	if generation := jwtUint64Claim(mapClaims, "client_generation"); generation != 0 {
		request.SetClientGeneration(generation)
	}
	if generation := jwtUint64Claim(mapClaims, "recovery_generation", "generation", "authorization_generation"); generation != 0 {
		request.SetRecoveryGeneration(generation)
	}
	if status := jwtStringClaim(mapClaims, "authorization_code_status", "code_status"); status != "" {
		request.SetAuthorizeCodeStatus(status)
	} else if consumed, ok := mapClaims["code_consumed"].(bool); ok && consumed {
		request.SetAuthorizeCodeStatus(fosite.AuthorizeCodeStatusConsumed)
	}
	if stage := jwtStringClaim(mapClaims, "rejection_stage", "failure_stage"); stage != "" {
		request.SetRejectionStage(stage)
	}
	if stage := jwtStringClaim(mapClaims, "recovery_stage", "authorize_code_stage"); stage != "" {
		request.SetAuthorizeCodeStage(stage)
	}

	return request
}

func jwtStringClaim(claims jwt.MapClaims, names ...string) string {
	for _, name := range names {
		if value, ok := claims[name].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func jwtUint64Claim(claims jwt.MapClaims, names ...string) uint64 {
	for _, name := range names {
		switch value := claims[name].(type) {
		case float64:
			if value > 0 {
				return uint64(value)
			}
		case int64:
			if value > 0 {
				return uint64(value)
			}
		case int:
			if value > 0 {
				return uint64(value)
			}
		case uint64:
			if value > 0 {
				return value
			}
		}
	}
	return 0
}

func (v *StatelessJWTValidator) IntrospectToken(ctx context.Context, token string, tokenUse fosite.TokenUse, accessRequest fosite.AccessRequester, scopes []string) (fosite.TokenUse, error) {
	t, err := validate(ctx, v.Signer, token)
	if err != nil {
		return "", err
	}

	// TODO: From here we assume it is an access token, but how do we know it is really and that is not an ID token?

	requester := AccessTokenJWTToRequest(t)

	if err := matchScopes(v.Config.GetScopeStrategy(ctx), requester.GetGrantedScopes(), scopes); err != nil {
		return fosite.AccessToken, err
	}

	accessRequest.Merge(requester)

	return fosite.AccessToken, nil
}
