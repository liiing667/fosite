// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// TokenStatusReport is the audit evidence produced for token introspection
// and token revocation. It intentionally contains a digest instead of the raw
// token, so reports can be logged without leaking bearer credentials.
//
// The report is attached to the introspection and revocation helpers that
// return it explicitly; the JSON representation of an introspection response
// is unchanged.
type TokenStatusReport struct {
	TokenDigest          string    `json:"token_digest"`
	TokenSignature       string    `json:"token_signature,omitempty"`
	ClientID             string    `json:"client_id,omitempty"`
	TokenUse             TokenUse  `json:"token_use,omitempty"`
	Active               bool      `json:"active"`
	Revoked              bool      `json:"revoked,omitempty"`
	Source               string    `json:"source,omitempty"`
	StatusSource         string    `json:"status_source,omitempty"`
	Generation           uint64    `json:"generation,omitempty"`            // durable revocation record sequence
	RevocationGeneration uint64    `json:"revocation_generation,omitempty"` // revoked generation of the token family
	RevokedAt            time.Time `json:"revoked_at,omitempty"`
	Stage                string    `json:"stage,omitempty"`
	FailureLocation      string    `json:"failure_location,omitempty"`
	Error                string    `json:"error,omitempty"`
}

// IntrospectionReport is the evidence returned by introspection helpers.
type IntrospectionReport = TokenStatusReport

// RevocationReport is the evidence returned by revocation helpers.
type RevocationReport = TokenStatusReport

const (
	// TokenStatusStageAuthentication identifies failures while authenticating
	// the client that requested introspection or revocation.
	TokenStatusStageAuthentication = "authentication"
	// TokenStatusStageIntrospection identifies failures while validating the
	// token that should be introspected.
	TokenStatusStageIntrospection = "introspection"
	// TokenStatusStageActive identifies a successful active introspection.
	TokenStatusStageActive = "active"
	// TokenStatusStageRevocation identifies failures while revoking a token.
	TokenStatusStageRevocation = "revocation"
	// TokenStatusStageNotFound identifies a token that no handler could find.
	TokenStatusStageNotFound = "not_found"
	// TokenStatusStageRevoked identifies a successful revocation.
	TokenStatusStageRevoked = "revoked"
)

// TokenRevocationRecord is the durable, storage-independent evidence for one
// revoked token digest. Stores may persist this record to keep revocation
// decisions stable across restarts.
type TokenRevocationRecord struct {
	TokenDigest          string    `json:"token_digest"`
	TokenSignature       string    `json:"token_signature,omitempty"`
	ClientID             string    `json:"client_id,omitempty"`
	TokenUse             TokenUse  `json:"token_use,omitempty"`
	RequestID            string    `json:"request_id,omitempty"`
	RevokedAt            time.Time `json:"revoked_at"`
	ExpiresAt            time.Time `json:"expires_at,omitempty"`
	Generation           uint64    `json:"generation,omitempty"`            // durable revocation record sequence
	RevocationGeneration uint64    `json:"revocation_generation,omitempty"` // revoked generation of the token family
	Source               string    `json:"source,omitempty"`
}

// TokenRevocationRecorder is an optional storage extension. Implementations
// persist revocation evidence before the revocation endpoint responds.
type TokenRevocationRecorder interface {
	RecordTokenRevocation(ctx context.Context, record TokenRevocationRecord) error
}

// TokenRevocationChecker is an optional storage extension used by stateless
// JWT introspection. It must return true for a digest that has been revoked
// and must keep that answer stable after a restart.
type TokenRevocationChecker interface {
	IsTokenRevoked(ctx context.Context, tokenDigest string) (bool, error)
}

// TokenRevocationStateProvider is an optional storage extension used to add
// generation and source evidence to introspection and revocation reports.
type TokenRevocationStateProvider interface {
	GetTokenRevocationState(ctx context.Context, tokenDigest string) (TokenRevocationRecord, error)
}

// TokenSignatureRevocationRecorder is an optional storage extension used to
// persist signature-keyed revocation markers. Unlike token sessions, these
// markers are available to stateless JWT introspection.
type TokenSignatureRevocationRecorder interface {
	RecordTokenSignatureRevocation(ctx context.Context, signature string, expiresAt time.Time) error
}

// TokenSignatureRevocationChecker is an optional storage extension used by
// stateless JWT introspection to recognize revoked JWT signatures.
type TokenSignatureRevocationChecker interface {
	IsTokenSignatureRevoked(ctx context.Context, signature string) (bool, error)
}

// TokenDigest returns a stable, non-reversible digest for audit reports. The
// raw token must never be written to a report or log.
func TokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
