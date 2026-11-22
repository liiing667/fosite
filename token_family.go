// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// TokenStatusStage* are stable stage identifiers used by revocation and
// introspection reports. They are intentionally plain strings so that they
// can be logged and compared without depending on internal error values.
const (
	TokenStatusStageAuthentication = "authentication"
	TokenStatusStageIntrospection  = "introspection"
	TokenStatusStageActive         = "active"
	TokenStatusStageRevocation     = "revocation"
	TokenStatusStageNotFound       = "not_found"
	TokenStatusStageRevoked        = "revoked"
	TokenStatusStageStorage        = "storage"
)

// TokenStatusReport is audit evidence produced by token revocation and token
// introspection. It is never serialized as part of the OAuth 2.0 response.
//
// A request family is the identifier shared by all access and refresh tokens
// that were issued for the same authorization request. RequestID and
// RequestFamily are aliases kept for consumers that use either name.
type TokenStatusReport struct {
	TokenDigest          string    `json:"token_digest"`
	TokenSignature       string    `json:"token_signature,omitempty"`
	ClientID             string    `json:"client_id,omitempty"`
	TokenUse             TokenUse  `json:"token_use,omitempty"`
	TokenType            TokenType `json:"token_type,omitempty"`
	RequestID            string    `json:"request_id,omitempty"`
	RequestFamily        string    `json:"request_family,omitempty"`
	Active               bool      `json:"active"`
	Revoked              bool      `json:"revoked,omitempty"`
	Source               string    `json:"source,omitempty"`
	StatusSource         string    `json:"status_source,omitempty"`
	Stage                string    `json:"stage,omitempty"`
	FailureLocation      string    `json:"failure_location,omitempty"`
	Error                string    `json:"error,omitempty"`
	Generation           uint64    `json:"generation,omitempty"`
	RevocationGeneration uint64    `json:"revocation_generation,omitempty"`
	RevokedAt            time.Time `json:"revoked_at,omitempty"`
}

// IntrospectionReport is an alias for TokenStatusReport.
type IntrospectionReport = TokenStatusReport

// RevocationReport is an alias for TokenStatusReport.
type RevocationReport = TokenStatusReport

// TokenFamilyRevocationRecord is durable evidence that a complete token
// family has been revoked. Stores should keep this record together with (not
// instead of) their token sessions so that a failed cleanup step can never
// make a revoked token active again.
type TokenFamilyRevocationRecord struct {
	RequestID      string    `json:"request_id"`
	ClientID       string    `json:"client_id,omitempty"`
	TokenType      TokenType `json:"token_type,omitempty"`
	TokenUse       TokenUse  `json:"token_use,omitempty"`
	TokenSignature string    `json:"token_signature,omitempty"`
	RevokedAt      time.Time `json:"revoked_at"`
	ExpiresAt      time.Time `json:"expires_at,omitempty"`
	Generation     uint64    `json:"generation,omitempty"`
	Source         string    `json:"source,omitempty"`
	Stage          string    `json:"stage,omitempty"`
}

// TokenRevocationRecord is durable evidence for one revoked token digest.
type TokenRevocationRecord struct {
	TokenDigest          string    `json:"token_digest"`
	TokenSignature       string    `json:"token_signature,omitempty"`
	ClientID             string    `json:"client_id,omitempty"`
	TokenUse             TokenUse  `json:"token_use,omitempty"`
	TokenType            TokenType `json:"token_type,omitempty"`
	RequestID            string    `json:"request_id,omitempty"`
	RequestFamily        string    `json:"request_family,omitempty"`
	RevokedAt            time.Time `json:"revoked_at"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	Generation           uint64    `json:"generation,omitempty"`
	RevocationGeneration uint64    `json:"revocation_generation,omitempty"`
	Source               string    `json:"source,omitempty"`
	Stage                string    `json:"stage,omitempty"`
}

// TokenFamilyRevoker atomically revokes every token belonging to a request
// family and leaves a durable family tombstone.
//
// Implementations must make a partial failure look like the complete old
// family: either no state is changed, or the tombstone is present before any
// cleanup starts. Once the tombstone is visible, token creation for the family
// must fail and token lookup/introspection must report the tokens as inactive.
type TokenFamilyRevoker interface {
	RevokeTokenFamily(ctx context.Context, requestID string) error
}

// TokenFamilyRevocationChecker reports whether a request family has a durable
// revocation tombstone.
type TokenFamilyRevocationChecker interface {
	IsTokenFamilyRevoked(ctx context.Context, requestID string) (bool, error)
}

// TokenFamilyRevocationStorage combines the family revocation operations.
type TokenFamilyRevocationStorage interface {
	TokenFamilyRevoker
	TokenFamilyRevocationChecker
}

// TokenFamilyRevocationStateProvider exposes the durable family tombstone.
type TokenFamilyRevocationStateProvider interface {
	GetTokenFamilyRevocation(ctx context.Context, requestID string) (TokenFamilyRevocationRecord, error)
}

// TokenFamilyResolution identifies the family that issued a token signature.
type TokenFamilyResolution struct {
	RequestID string
	ClientID  string
}

// TokenFamilyResolver is an optional storage extension that can resolve a
// token signature to its request family even after the token session itself
// has been rotated out or deleted. Revocation uses it to close the race where
// a concurrent refresh removes the presented access token before the
// revocation request has read its family identity.
type TokenFamilyResolver interface {
	ResolveTokenFamily(ctx context.Context, tokenType TokenType, signature string) (TokenFamilyResolution, error)
}

// TokenFamilyRevocationRecorder is an optional storage extension used to
// enrich a family tombstone with the token type, client and failure stage that
// caused the revocation.
type TokenFamilyRevocationRecorder interface {
	RecordTokenFamilyRevocation(ctx context.Context, record TokenFamilyRevocationRecord) error
}

// TokenRevocationRecorder is an optional storage extension used to persist
// revocation evidence for audit and stateless introspection.
type TokenRevocationRecorder interface {
	RecordTokenRevocation(ctx context.Context, record TokenRevocationRecord) error
}

// TokenRevocationChecker is an optional storage extension used by stateless
// token introspection.
type TokenRevocationChecker interface {
	IsTokenRevoked(ctx context.Context, tokenDigest string) (bool, error)
}

// TokenRevocationStateProvider exposes durable revocation evidence.
type TokenRevocationStateProvider interface {
	GetTokenRevocationState(ctx context.Context, tokenDigest string) (TokenRevocationRecord, error)
}

// TokenSignatureRevocationRecorder is an optional storage extension used to
// persist signature-keyed revocation markers.
type TokenSignatureRevocationRecorder interface {
	RecordTokenSignatureRevocation(ctx context.Context, signature string, expiresAt time.Time) error
}

// TokenSignatureRevocationChecker recognizes signature-keyed revocation
// markers. It is used by stateless JWT introspection.
type TokenSignatureRevocationChecker interface {
	IsTokenSignatureRevoked(ctx context.Context, signature string) (bool, error)
}

// RevocationHandlerWithReport is implemented by revocation handlers that can
// expose the evidence collected while revoking a token.
type RevocationHandlerWithReport interface {
	RevokeTokenWithReport(ctx context.Context, token string, tokenType TokenType, client Client) (TokenStatusReport, error)
}

// TokenDigest returns a stable, non-reversible digest suitable for audit
// reports. Raw bearer tokens must never be written to logs.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
