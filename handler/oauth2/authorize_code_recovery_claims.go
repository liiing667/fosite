// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
)

// setAuthorizeCodeRecoverySessionClaims mirrors the frozen request metadata
// into JWT sessions so that stateful and stateless introspection consumers see
// the same client version, recovery generation and code status.
func setAuthorizeCodeRecoverySessionClaims(requester fosite.AccessRequester, clientRevision string, clientGeneration, generation uint64) {
	if requester == nil {
		return
	}
	jwtSession, ok := requester.GetSession().(*JWTSession)
	if !ok || jwtSession == nil {
		return
	}

	if jwtSession.JWTClaims == nil {
		jwtSession.JWTClaims = &jwt.JWTClaims{}
	}
	if jwtSession.JWTClaims.Extra == nil {
		jwtSession.JWTClaims.Extra = map[string]interface{}{}
	}
	extra := jwtSession.JWTClaims.Extra

	if clientRevision != "" {
		extra["client_version"] = clientRevision
		extra["client_revision"] = clientRevision
		extra["client_authentication_version"] = clientRevision
		if clientGeneration == 0 {
			clientGeneration = fosite.ClientRevisionGeneration(clientRevision)
		}
		extra["client_generation"] = clientGeneration
	}
	if generation != 0 {
		extra["recovery_generation"] = generation
		extra["generation"] = generation
		extra["authorization_generation"] = generation
	}
	extra["authorization_code_status"] = fosite.AuthorizeCodeStatusConsumed
	extra["code_status"] = fosite.AuthorizeCodeStatusConsumed
	extra["authorization_code_consumed"] = true
	extra["code_consumed"] = true
	extra["recovery_stage"] = fosite.RecoveryStageAuthorizeCodeConsumed
}
