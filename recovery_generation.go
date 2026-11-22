// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

// Authorization code lifecycle states. They are stored together with the
// authorization request so that every consumer (token endpoint, storage and
// introspection) observes the same state.
const (
	AuthorizeCodeStatusAuthorized  = "authorized"
	AuthorizeCodeStatusActive      = "active"
	AuthorizeCodeStatusConsumed    = "consumed"
	AuthorizeCodeStatusInvalidated = "invalidated"
	AuthorizeCodeStatusRejected    = "rejected"
)

// Recovery stages describe where an authorization-code exchange stopped. They
// are deliberately stable strings so that logs, token responses and
// introspection reports can be correlated without exposing internal errors.
const (
	RecoveryStageAuthorizeRequest      = "authorize_request"
	RecoveryStageAuthorizeCodeIssued   = "authorize_code_issued"
	RecoveryStageAuthorizeCodeActive   = "authorize_code_active"
	RecoveryStageAuthorizeCodeLookup   = "authorize_code_lookup"
	RecoveryStageAuthorizeCodeClaim    = "authorize_code_claim"
	RecoveryStageAuthorizeCodeConsumed = "authorize_code_consumed"
	RecoveryStageClientRevision        = "client_revision"
	RecoveryStageRedirectURI           = "redirect_uri"
	RecoveryStageTokenCreation         = "token_creation"
	RecoveryStageTokenValidation       = "token_validation"
	RecoveryStageIntrospection         = "introspection"
)

// ClientWithRevision is implemented by clients that expose an explicit
// registration revision. It is optional; clients without it are fingerprinted
// from their complete serialized registration.
type ClientWithRevision interface {
	Client
	GetClientRevision() string
}

// ClientWithGeneration is implemented by clients that expose a numeric
// registration generation. It is optional.
type ClientWithGeneration interface {
	Client
	GetClientGeneration() uint64
}

// ClientWithAuthenticationVersion is implemented by clients that expose a
// client authentication revision alias.
type ClientWithAuthenticationVersion interface {
	Client
	GetClientAuthenticationVersion() string
}

// ClientRevisionRequester is implemented by requesters that carry the client
// registration revision used for the request.
type ClientRevisionRequester interface {
	Requester
	GetClientRevision() string
	GetClientVersion() string
	GetClientGeneration() uint64
	GetClientAuthenticationVersion() string
}

// RecoveryGenerationRequester is implemented by requesters that carry the
// authorization-code recovery generation and its lifecycle evidence.
type RecoveryGenerationRequester interface {
	Requester
	GetRecoveryGeneration() uint64
	GetGeneration() uint64
	GetAuthorizeCodeStatus() string
	GetAuthorizationCodeStatus() string
	GetRejectionStage() string
	GetFailureStage() string
}

// AuthorizeCodeRecoveryRequester is an alias for RecoveryGenerationRequester.
type AuthorizeCodeRecoveryRequester = RecoveryGenerationRequester

// ClientAuthenticationVersionRequester is an alias for
// ClientRevisionRequester.
type ClientAuthenticationVersionRequester = ClientRevisionRequester

type clientRevisionContextKey struct{}

// WithClientRevision attaches the revision of the client that is currently
// authenticating to the context. Storage implementations can use it to keep a
// tombstone bound to the client version that consumed an authorization code.
func WithClientRevision(ctx context.Context, revision string) context.Context {
	return context.WithValue(ctx, clientRevisionContextKey{}, revision)
}

// ClientRevisionFromContext returns the client revision attached with
// WithClientRevision.
func ClientRevisionFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	revision, _ := ctx.Value(clientRevisionContextKey{}).(string)
	return revision
}

var lastRecoveryGeneration atomic.Uint64

// NextRecoveryGeneration returns a process-wide monotonic generation. The
// value is persisted in the authorization request and inherited by all tokens
// created from the same authorization-code transaction.
func NextRecoveryGeneration() uint64 {
	for {
		last := lastRecoveryGeneration.Load()
		// Millisecond precision keeps the value exactly representable in
		// IEEE-754 doubles, so JSON/JWT consumers do not round it while still
		// providing a monotonic, restart-safe generation.
		next := uint64(time.Now().UTC().UnixMilli())
		if next <= last {
			next = last + 1
		}
		if lastRecoveryGeneration.CompareAndSwap(last, next) {
			return next
		}
	}
}

// NewRecoveryGeneration is an alias for NextRecoveryGeneration.
func NewRecoveryGeneration() uint64 {
	return NextRecoveryGeneration()
}

// ClientRevision returns a stable fingerprint of the complete client
// registration. The fingerprint is the authority for "same client version" and
// intentionally includes hashed secrets, rotated hashes, redirect URIs, scopes,
// audiences, grant/response types and the public flag.
//
// If a client implements ClientWithRevision and returns a non-empty revision,
// that value is used as an explicit revision.
func ClientRevision(client Client) string {
	if client == nil {
		return ""
	}

	if revisionClient, ok := client.(ClientWithRevision); ok {
		if revision := strings.TrimSpace(revisionClient.GetClientRevision()); revision != "" {
			return revision
		}
	}
	if versionClient, ok := client.(ClientWithAuthenticationVersion); ok {
		if version := strings.TrimSpace(versionClient.GetClientAuthenticationVersion()); version != "" {
			return version
		}
	}

	payload, err := json.Marshal(client)
	if err != nil {
		payload = []byte(fmt.Sprintf("%v", client))
	}

	hash := sha256.New()
	_, _ = hash.Write([]byte(fmt.Sprintf("%T", client)))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write([]byte(client.GetID()))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(payload)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// ClientVersion is an alias for ClientRevision.
func ClientVersion(client Client) string {
	return ClientRevision(client)
}

// ClientFingerprint is an alias for ClientRevision.
func ClientFingerprint(client Client) string {
	return ClientRevision(client)
}

// ClientRevisionGeneration derives a stable numeric generation from a client
// revision.
func ClientRevisionGeneration(revision string) uint64 {
	if revision == "" {
		return 0
	}
	sum := sha256.Sum256([]byte(revision))
	// Keep the generation within the exact integer range of JSON numbers.
	return binary.BigEndian.Uint64(sum[:8]) & ((1 << 53) - 1)
}

// ClientGeneration returns the numeric generation of a client registration.
func ClientGeneration(client Client) uint64 {
	if client == nil {
		return 0
	}
	if generationClient, ok := client.(ClientWithGeneration); ok {
		if generation := generationClient.GetClientGeneration(); generation != 0 {
			return generation
		}
	}
	return ClientRevisionGeneration(ClientRevision(client))
}

// ClientRevisionCompatible reports whether tokenClient may redeem an
// authorization issued to authorizeClient.
//
// Same registration revisions are always compatible. A confidential client is
// also compatible when the current registration still retains the old primary
// secret as a rotated secret (the explicit client-secret rotation window).
// Public clients remain compatible by client ID because they have no secret
// authentication, while PKCE and the frozen redirect URI continue to protect
// the exchange.
func ClientRevisionCompatible(authorizeClient, tokenClient Client) bool {
	if authorizeClient == nil || tokenClient == nil {
		return false
	}
	if authorizeClient.GetID() != tokenClient.GetID() {
		return false
	}
	if ClientRevision(authorizeClient) == ClientRevision(tokenClient) {
		return true
	}
	if authorizeClient.IsPublic() && tokenClient.IsPublic() {
		return true
	}

	oldSecret := authorizeClient.GetHashedSecret()
	if len(oldSecret) > 0 {
		if rotated, ok := tokenClient.(ClientWithSecretRotation); ok {
			for _, hash := range rotated.GetRotatedHashes() {
				if bytes.Equal(hash, oldSecret) {
					return true
				}
			}
		}
	}

	currentSecret := tokenClient.GetHashedSecret()
	if len(currentSecret) > 0 {
		if rotated, ok := authorizeClient.(ClientWithSecretRotation); ok {
			for _, hash := range rotated.GetRotatedHashes() {
				if bytes.Equal(hash, currentSecret) {
					return true
				}
			}
		}
	}

	return false
}

// RequesterClientRevision returns the frozen client revision of a requester.
func RequesterClientRevision(requester Requester) string {
	if requester == nil {
		return ""
	}
	if revisionRequester, ok := requester.(interface{ GetClientRevision() string }); ok {
		if revision := revisionRequester.GetClientRevision(); revision != "" {
			return revision
		}
	}
	if versionRequester, ok := requester.(interface{ GetClientVersion() string }); ok {
		return versionRequester.GetClientVersion()
	}
	return ""
}

// SetRequesterClientRevision stores the client revision and its aliases on a
// requester that supports metadata.
func SetRequesterClientRevision(requester Requester, revision string) {
	if requester == nil || revision == "" {
		return
	}
	if setter, ok := requester.(interface{ SetClientRevision(string) }); ok {
		setter.SetClientRevision(revision)
	}
	if setter, ok := requester.(interface{ SetClientVersion(string) }); ok {
		setter.SetClientVersion(revision)
	}
	if setter, ok := requester.(interface{ SetClientAuthenticationVersion(string) }); ok {
		setter.SetClientAuthenticationVersion(revision)
	}
	if setter, ok := requester.(interface{ SetClientGeneration(uint64) }); ok {
		setter.SetClientGeneration(ClientRevisionGeneration(revision))
	}
}

// RequesterClientGeneration returns the numeric client generation.
func RequesterClientGeneration(requester Requester) uint64 {
	if requester == nil {
		return 0
	}
	if generationRequester, ok := requester.(interface{ GetClientGeneration() uint64 }); ok {
		if generation := generationRequester.GetClientGeneration(); generation != 0 {
			return generation
		}
	}
	return ClientRevisionGeneration(RequesterClientRevision(requester))
}

// SetRequesterClientGeneration stores a numeric client generation.
func SetRequesterClientGeneration(requester Requester, generation uint64) {
	if requester == nil || generation == 0 {
		return
	}
	if setter, ok := requester.(interface{ SetClientGeneration(uint64) }); ok {
		setter.SetClientGeneration(generation)
	}
}

// RequesterClientSecretHash returns the hashed primary secret frozen on the
// requester.
func RequesterClientSecretHash(requester Requester) []byte {
	if requester == nil {
		return nil
	}
	if hashRequester, ok := requester.(interface{ GetClientSecretHash() []byte }); ok {
		return hashRequester.GetClientSecretHash()
	}
	return nil
}

// SetRequesterClientSecretHash stores the hashed primary secret frozen on the
// requester.
func SetRequesterClientSecretHash(requester Requester, secretHash []byte) {
	if requester == nil || len(secretHash) == 0 {
		return
	}
	if setter, ok := requester.(interface{ SetClientSecretHash([]byte) }); ok {
		setter.SetClientSecretHash(secretHash)
	}
}

// RequesterClientPublic returns the frozen public-client flag.
func RequesterClientPublic(requester Requester) bool {
	if requester == nil {
		return false
	}
	if publicRequester, ok := requester.(interface{ GetClientPublic() bool }); ok {
		return publicRequester.GetClientPublic()
	}
	return false
}

// SetRequesterClientPublic stores the frozen public-client flag.
func SetRequesterClientPublic(requester Requester, public bool) {
	if requester == nil {
		return
	}
	if setter, ok := requester.(interface{ SetClientPublic(bool) }); ok {
		setter.SetClientPublic(public)
	}
}

// RequesterRecoveryGeneration returns the persisted recovery generation.
func RequesterRecoveryGeneration(requester Requester) uint64 {
	if requester == nil {
		return 0
	}
	if generationRequester, ok := requester.(interface{ GetRecoveryGeneration() uint64 }); ok {
		if generation := generationRequester.GetRecoveryGeneration(); generation != 0 {
			return generation
		}
	}
	if generationRequester, ok := requester.(interface{ GetGeneration() uint64 }); ok {
		if generation := generationRequester.GetGeneration(); generation != 0 {
			return generation
		}
	}
	if generationRequester, ok := requester.(interface{ GetCodeGeneration() uint64 }); ok {
		return generationRequester.GetCodeGeneration()
	}
	return 0
}

// SetRequesterRecoveryGeneration stores the recovery generation and its alias.
func SetRequesterRecoveryGeneration(requester Requester, generation uint64) {
	if requester == nil || generation == 0 {
		return
	}
	if setter, ok := requester.(interface{ SetRecoveryGeneration(uint64) }); ok {
		setter.SetRecoveryGeneration(generation)
	}
	if setter, ok := requester.(interface{ SetGeneration(uint64) }); ok {
		setter.SetGeneration(generation)
	}
	if setter, ok := requester.(interface{ SetAuthorizeCodeGeneration(uint64) }); ok {
		setter.SetAuthorizeCodeGeneration(generation)
	}
	if setter, ok := requester.(interface{ SetCodeGeneration(uint64) }); ok {
		setter.SetCodeGeneration(generation)
	}
}

// EnsureRecoveryGeneration returns the existing recovery generation or creates
// one and stores it on the requester.
func EnsureRecoveryGeneration(requester Requester) uint64 {
	if requester == nil {
		return 0
	}
	if generation := RequesterRecoveryGeneration(requester); generation != 0 {
		return generation
	}
	generation := NextRecoveryGeneration()
	SetRequesterRecoveryGeneration(requester, generation)
	return generation
}

// RequesterAuthorizeCodeStatus returns the authorization-code lifecycle state.
func RequesterAuthorizeCodeStatus(requester Requester) string {
	if requester == nil {
		return ""
	}
	if statusRequester, ok := requester.(interface{ GetAuthorizeCodeStatus() string }); ok {
		if status := statusRequester.GetAuthorizeCodeStatus(); status != "" {
			return status
		}
	}
	if statusRequester, ok := requester.(interface{ GetAuthorizationCodeStatus() string }); ok {
		return statusRequester.GetAuthorizationCodeStatus()
	}
	return ""
}

// SetRequesterAuthorizeCodeStatus stores the authorization-code lifecycle state
// and its aliases.
func SetRequesterAuthorizeCodeStatus(requester Requester, status string) {
	if requester == nil || status == "" {
		return
	}
	if setter, ok := requester.(interface{ SetAuthorizeCodeStatus(string) }); ok {
		setter.SetAuthorizeCodeStatus(status)
	}
	if setter, ok := requester.(interface{ SetAuthorizationCodeStatus(string) }); ok {
		setter.SetAuthorizationCodeStatus(status)
	}
	if setter, ok := requester.(interface{ SetCodeStatus(string) }); ok {
		setter.SetCodeStatus(status)
	}
}

// RequesterAuthorizeCodeStage returns the last completed lifecycle stage.
func RequesterAuthorizeCodeStage(requester Requester) string {
	if requester == nil {
		return ""
	}
	if stageRequester, ok := requester.(interface{ GetAuthorizeCodeStage() string }); ok {
		return stageRequester.GetAuthorizeCodeStage()
	}
	return ""
}

// SetRequesterAuthorizeCodeStage stores the last completed lifecycle stage.
func SetRequesterAuthorizeCodeStage(requester Requester, stage string) {
	if requester == nil || stage == "" {
		return
	}
	if setter, ok := requester.(interface{ SetAuthorizeCodeStage(string) }); ok {
		setter.SetAuthorizeCodeStage(stage)
	}
}

// RequesterAuthorizationRedirectURI returns the redirect URI frozen at the
// authorization endpoint.
func RequesterAuthorizationRedirectURI(requester Requester) string {
	if requester == nil {
		return ""
	}
	if redirectRequester, ok := requester.(interface{ GetAuthorizationRedirectURI() string }); ok {
		return redirectRequester.GetAuthorizationRedirectURI()
	}
	return ""
}

// SetRequesterAuthorizationRedirectURI stores the redirect URI frozen at the
// authorization endpoint.
func SetRequesterAuthorizationRedirectURI(requester Requester, redirectURI string) {
	if requester == nil || redirectURI == "" {
		return
	}
	if setter, ok := requester.(interface{ SetAuthorizationRedirectURI(string) }); ok {
		setter.SetAuthorizationRedirectURI(redirectURI)
	}
}

// RequesterRejectionStage returns the stage at which a request was rejected.
func RequesterRejectionStage(requester Requester) string {
	if requester == nil {
		return ""
	}
	if stageRequester, ok := requester.(interface{ GetRejectionStage() string }); ok {
		if stage := stageRequester.GetRejectionStage(); stage != "" {
			return stage
		}
	}
	if stageRequester, ok := requester.(interface{ GetFailureStage() string }); ok {
		return stageRequester.GetFailureStage()
	}
	return ""
}

// SetRequesterRejectionStage stores the rejection stage and its alias.
func SetRequesterRejectionStage(requester Requester, stage string) {
	if requester == nil {
		return
	}
	if setter, ok := requester.(interface{ SetRejectionStage(string) }); ok {
		setter.SetRejectionStage(stage)
	}
	if setter, ok := requester.(interface{ SetFailureStage(string) }); ok {
		setter.SetFailureStage(stage)
	}
}

// PrepareAuthorizeRequestMetadata freezes the client registration revision,
// redirect URI and recovery generation on an authorization request. It is
// idempotent and is also used when reviving legacy serialized requests.
func PrepareAuthorizeRequestMetadata(requester AuthorizeRequester) {
	if requester == nil {
		return
	}

	client := requester.GetClient()
	if RequesterClientRevision(requester) == "" {
		SetRequesterClientRevision(requester, ClientRevision(client))
	}
	if client != nil {
		SetRequesterClientGeneration(requester, ClientGeneration(client))
	}
	if len(RequesterClientSecretHash(requester)) == 0 && client != nil {
		SetRequesterClientSecretHash(requester, client.GetHashedSecret())
		SetRequesterClientPublic(requester, client.IsPublic())
	}
	EnsureRecoveryGeneration(requester)

	if RequesterAuthorizationRedirectURI(requester) == "" {
		if redirectURI := requester.GetRequestForm().Get("redirect_uri"); redirectURI != "" {
			SetRequesterAuthorizationRedirectURI(requester, redirectURI)
		}
	}
	if RequesterAuthorizeCodeStatus(requester) == "" {
		SetRequesterAuthorizeCodeStatus(requester, AuthorizeCodeStatusAuthorized)
		SetRequesterAuthorizeCodeStage(requester, RecoveryStageAuthorizeRequest)
	}
}

// ClientRevisionCompatibleWithRequest reports whether tokenClient may redeem an
// authorization represented by authorizeRequest. It uses the frozen revision,
// secret hash and public flag first so that in-place mutation of the stored
// client object cannot erase the old registration identity.
func ClientRevisionCompatibleWithRequest(authorizeRequest Requester, tokenClient Client) bool {
	if authorizeRequest == nil || tokenClient == nil {
		return false
	}

	storedRevision := RequesterClientRevision(authorizeRequest)
	currentRevision := ClientRevision(tokenClient)
	if storedRevision == "" {
		return authorizeRequest.GetClient() == nil ||
			authorizeRequest.GetClient().GetID() == tokenClient.GetID()
	}
	if storedRevision == currentRevision {
		return true
	}

	if storedSecretHash := RequesterClientSecretHash(authorizeRequest); len(storedSecretHash) > 0 {
		if rotated, ok := tokenClient.(ClientWithSecretRotation); ok {
			for _, hash := range rotated.GetRotatedHashes() {
				if bytes.Equal(hash, storedSecretHash) {
					return true
				}
			}
		}
	}

	if RequesterClientPublic(authorizeRequest) && tokenClient.IsPublic() {
		return true
	}

	// Legacy sessions that have a revision but no frozen secret metadata still
	// use the object-based compatibility check.
	if len(RequesterClientSecretHash(authorizeRequest)) == 0 && !RequesterClientPublic(authorizeRequest) {
		return ClientRevisionCompatible(authorizeRequest.GetClient(), tokenClient)
	}

	return false
}

// PrepareAuthorizeCodeRequest freezes metadata and marks a new authorization
// code as active. It must be called before the code session is persisted.
func PrepareAuthorizeCodeRequest(requester AuthorizeRequester) {
	if requester == nil {
		return
	}
	PrepareAuthorizeRequestMetadata(requester)
	SetRequesterAuthorizeCodeStatus(requester, AuthorizeCodeStatusActive)
	SetRequesterAuthorizeCodeStage(requester, RecoveryStageAuthorizeCodeIssued)
}
