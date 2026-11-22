// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"net/url"
	"time"

	"github.com/google/uuid"
	"golang.org/x/text/language"
)

// Request is an implementation of Requester
type Request struct {
	ID                string       `json:"id" gorethink:"id"`
	RequestedAt       time.Time    `json:"requestedAt" gorethink:"requestedAt"`
	Client            Client       `json:"client" gorethink:"client"`
	RequestedScope    Arguments    `json:"scopes" gorethink:"scopes"`
	GrantedScope      Arguments    `json:"grantedScopes" gorethink:"grantedScopes"`
	Form              url.Values   `json:"form" gorethink:"form"`
	Session           Session      `json:"session" gorethink:"session"`
	RequestedAudience Arguments    `json:"requestedAudience"`
	GrantedAudience   Arguments    `json:"grantedAudience"`
	Lang              language.Tag `json:"-"`

	// ClientRevision is the frozen fingerprint of the client registration that
	// initiated this transaction. ClientVersion and
	// ClientAuthenticationVersion are compatibility aliases.
	ClientRevision              string `json:"clientRevision,omitempty" gorethink:"clientRevision"`
	ClientVersion               string `json:"clientVersion,omitempty" gorethink:"clientVersion"`
	ClientAuthenticationVersion string `json:"clientAuthenticationVersion,omitempty" gorethink:"clientAuthenticationVersion"`
	ClientGeneration            uint64 `json:"clientGeneration,omitempty" gorethink:"clientGeneration"`
	// ClientSecretHash is the hashed primary secret frozen at authorization
	// time. It lets a rotated registration prove lineage even if the original
	// client object was mutated in place.
	ClientSecretHash []byte `json:"clientSecretHash,omitempty" gorethink:"clientSecretHash"`
	// ClientPublic is the public-client flag frozen at authorization time.
	ClientPublic bool `json:"clientPublic,omitempty" gorethink:"clientPublic"`

	// RecoveryGeneration is the single generation shared by the authorization
	// code, its consumption record and the tokens issued from it. Generation,
	// AuthorizeCodeGeneration and AuthorizationGeneration are aliases kept for
	// consumers that use different vocabulary.
	RecoveryGeneration      uint64 `json:"recoveryGeneration,omitempty" gorethink:"recoveryGeneration"`
	Generation              uint64 `json:"generation,omitempty" gorethink:"generation"`
	AuthorizeCodeGeneration uint64 `json:"authorizeCodeGeneration,omitempty" gorethink:"authorizeCodeGeneration"`
	AuthorizationGeneration uint64 `json:"authorizationGeneration,omitempty" gorethink:"authorizationGeneration"`
	CodeGeneration          uint64 `json:"codeGeneration,omitempty" gorethink:"codeGeneration"`

	// AuthorizeCodeStatus records the lifecycle state of the authorization
	// code that produced this request. CodeStatus and AuthorizationCodeStatus
	// are aliases used by different consumers.
	AuthorizeCodeStatus     string `json:"authorizeCodeStatus,omitempty" gorethink:"authorizeCodeStatus"`
	AuthorizationCodeStatus string `json:"authorizationCodeStatus,omitempty" gorethink:"authorizationCodeStatus"`
	CodeStatus              string `json:"codeStatus,omitempty" gorethink:"codeStatus"`
	AuthorizeCodeStage      string `json:"authorizeCodeStage,omitempty" gorethink:"authorizeCodeStage"`

	// RejectionStage records the stage that rejected the transaction.
	// FailureStage is an alias.
	RejectionStage string `json:"rejectionStage,omitempty" gorethink:"rejectionStage"`
	FailureStage   string `json:"failureStage,omitempty" gorethink:"failureStage"`

	// AuthorizationRedirectURI is the exact redirect URI sent to the
	// authorization endpoint. It is kept outside the configurable sanitation
	// whitelist so that a custom whitelist cannot drop the redirect binding.
	AuthorizationRedirectURI string `json:"authorizationRedirectUri,omitempty" gorethink:"authorizationRedirectUri"`
}

func NewRequest() *Request {
	return &Request{
		Client:            &DefaultClient{},
		RequestedScope:    Arguments{},
		RequestedAudience: Arguments{},
		GrantedAudience:   Arguments{},
		GrantedScope:      Arguments{},
		Form:              url.Values{},
		RequestedAt:       time.Now().UTC(),
	}
}

func (a *Request) GetID() string {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return a.ID
}

func (a *Request) SetID(id string) {
	a.ID = id
}

func (a *Request) GetRequestForm() url.Values {
	return a.Form
}

func (a *Request) GetRequestedAt() time.Time {
	return a.RequestedAt
}

func (a *Request) GetClient() Client {
	return a.Client
}

func (a *Request) GetRequestedScopes() Arguments {
	return a.RequestedScope
}

func (a *Request) SetRequestedScopes(s Arguments) {
	a.RequestedScope = nil
	for _, scope := range s {
		a.AppendRequestedScope(scope)
	}
}

func (a *Request) SetRequestedAudience(s Arguments) {
	a.RequestedAudience = nil
	for _, scope := range s {
		a.AppendRequestedAudience(scope)
	}
}

func (a *Request) AppendRequestedScope(scope string) {
	for _, has := range a.RequestedScope {
		if scope == has {
			return
		}
	}
	a.RequestedScope = append(a.RequestedScope, scope)
}

func (a *Request) AppendRequestedAudience(audience string) {
	for _, has := range a.RequestedAudience {
		if audience == has {
			return
		}
	}
	a.RequestedAudience = append(a.RequestedAudience, audience)
}

func (a *Request) GetRequestedAudience() (audience Arguments) {
	return a.RequestedAudience
}

func (a *Request) GrantAudience(audience string) {
	for _, has := range a.GrantedAudience {
		if audience == has {
			return
		}
	}
	a.GrantedAudience = append(a.GrantedAudience, audience)
}

func (a *Request) GetGrantedScopes() Arguments {
	return a.GrantedScope
}

func (a *Request) GetGrantedAudience() Arguments {
	return a.GrantedAudience
}

func (a *Request) GrantScope(scope string) {
	for _, has := range a.GrantedScope {
		if scope == has {
			return
		}
	}
	a.GrantedScope = append(a.GrantedScope, scope)
}

func (a *Request) SetSession(session Session) {
	a.Session = session
}

func (a *Request) GetSession() Session {
	return a.Session
}

func (a *Request) Merge(request Requester) {
	for _, scope := range request.GetRequestedScopes() {
		a.AppendRequestedScope(scope)
	}
	for _, scope := range request.GetGrantedScopes() {
		a.GrantScope(scope)
	}

	for _, aud := range request.GetRequestedAudience() {
		a.AppendRequestedAudience(aud)
	}
	for _, aud := range request.GetGrantedAudience() {
		a.GrantAudience(aud)
	}

	a.ID = request.GetID()
	a.RequestedAt = request.GetRequestedAt()
	a.Client = request.GetClient()
	a.Session = request.GetSession()

	for k, v := range request.GetRequestForm() {
		a.Form[k] = v
	}

	if revision := RequesterClientRevision(request); revision != "" {
		a.SetClientRevision(revision)
	}
	if generation := RequesterClientGeneration(request); generation != 0 {
		a.SetClientGeneration(generation)
	}
	if generation := RequesterRecoveryGeneration(request); generation != 0 {
		a.SetRecoveryGeneration(generation)
	}
	if secretHash := RequesterClientSecretHash(request); len(secretHash) > 0 {
		a.SetClientSecretHash(secretHash)
	}
	if RequesterClientRevision(request) != "" || RequesterClientPublic(request) {
		a.SetClientPublic(RequesterClientPublic(request))
	}
	if status := RequesterAuthorizeCodeStatus(request); status != "" {
		a.SetAuthorizeCodeStatus(status)
	}
	if stage := RequesterAuthorizeCodeStage(request); stage != "" {
		a.SetAuthorizeCodeStage(stage)
	}
	if redirectURI := RequesterAuthorizationRedirectURI(request); redirectURI != "" {
		a.SetAuthorizationRedirectURI(redirectURI)
	}
	if stage := RequesterRejectionStage(request); stage != "" {
		a.SetRejectionStage(stage)
	}
}

var defaultAllowedParameters = []string{"grant_type", "response_type", "scope", "client_id"}

func (a *Request) Sanitize(allowedParameters []string) Requester {
	b := new(Request)
	allowed := map[string]bool{}
	for _, v := range append(allowedParameters, defaultAllowedParameters...) {
		allowed[v] = true
	}

	*b = *a
	b.ID = a.GetID()
	b.Form = url.Values{}
	for k := range a.Form {
		if allowed[k] {
			b.Form[k] = a.Form[k]
		}
	}

	return b
}

func (a *Request) GetLang() language.Tag {
	return a.Lang
}

// GetClientRevision returns the frozen client registration revision.
func (a *Request) GetClientRevision() string {
	if a == nil {
		return ""
	}
	if a.ClientRevision != "" {
		return a.ClientRevision
	}
	return a.ClientVersion
}

// SetClientRevision sets the frozen client registration revision and its
// compatibility aliases.
func (a *Request) SetClientRevision(revision string) {
	if a == nil {
		return
	}
	a.ClientRevision = revision
	a.ClientVersion = revision
	a.ClientAuthenticationVersion = revision
	if a.ClientGeneration == 0 {
		a.ClientGeneration = ClientRevisionGeneration(revision)
	}
}

// GetClientVersion returns the client registration revision.
func (a *Request) GetClientVersion() string {
	return a.GetClientRevision()
}

// SetClientVersion sets the client registration revision.
func (a *Request) SetClientVersion(revision string) {
	a.SetClientRevision(revision)
}

// GetClientAuthenticationVersion returns the client authentication revision.
func (a *Request) GetClientAuthenticationVersion() string {
	if a == nil {
		return ""
	}
	if a.ClientAuthenticationVersion != "" {
		return a.ClientAuthenticationVersion
	}
	return a.GetClientRevision()
}

// SetClientAuthenticationVersion sets the client authentication revision.
func (a *Request) SetClientAuthenticationVersion(revision string) {
	a.SetClientRevision(revision)
}

// GetClientAuthVersion returns the client authentication revision.
func (a *Request) GetClientAuthVersion() string {
	return a.GetClientRevision()
}

// SetClientAuthVersion sets the client authentication revision.
func (a *Request) SetClientAuthVersion(revision string) {
	a.SetClientRevision(revision)
}

// GetClientGeneration returns the numeric client registration generation.
func (a *Request) GetClientGeneration() uint64 {
	if a == nil {
		return 0
	}
	if a.ClientGeneration != 0 {
		return a.ClientGeneration
	}
	return ClientRevisionGeneration(a.GetClientRevision())
}

// SetClientGeneration sets the numeric client registration generation.
func (a *Request) SetClientGeneration(generation uint64) {
	if a != nil {
		a.ClientGeneration = generation
	}
}

// GetClientSecretHash returns the hashed primary secret frozen at
// authorization time.
func (a *Request) GetClientSecretHash() []byte {
	if a == nil {
		return nil
	}
	return a.ClientSecretHash
}

// SetClientSecretHash sets the hashed primary secret frozen at authorization
// time.
func (a *Request) SetClientSecretHash(secretHash []byte) {
	if a == nil {
		return
	}
	a.ClientSecretHash = append([]byte(nil), secretHash...)
}

// GetClientPublic returns the public-client flag frozen at authorization time.
func (a *Request) GetClientPublic() bool {
	if a == nil {
		return false
	}
	return a.ClientPublic
}

// SetClientPublic sets the public-client flag frozen at authorization time.
func (a *Request) SetClientPublic(public bool) {
	if a != nil {
		a.ClientPublic = public
	}
}

// GetRecoveryGeneration returns the generation shared by the authorization
// code and all tokens issued from it.
func (a *Request) GetRecoveryGeneration() uint64 {
	if a == nil {
		return 0
	}
	if a.RecoveryGeneration != 0 {
		return a.RecoveryGeneration
	}
	if a.Generation != 0 {
		return a.Generation
	}
	if a.AuthorizeCodeGeneration != 0 {
		return a.AuthorizeCodeGeneration
	}
	if a.AuthorizationGeneration != 0 {
		return a.AuthorizationGeneration
	}
	return a.CodeGeneration
}

// SetRecoveryGeneration sets the recovery generation and its aliases.
func (a *Request) SetRecoveryGeneration(generation uint64) {
	if a == nil {
		return
	}
	a.RecoveryGeneration = generation
	a.Generation = generation
	a.AuthorizeCodeGeneration = generation
	a.AuthorizationGeneration = generation
	a.CodeGeneration = generation
}

// GetGeneration returns the recovery generation.
func (a *Request) GetGeneration() uint64 {
	return a.GetRecoveryGeneration()
}

// SetGeneration sets the recovery generation.
func (a *Request) SetGeneration(generation uint64) {
	a.SetRecoveryGeneration(generation)
}

// GetAuthorizeCodeGeneration returns the authorization-code generation.
func (a *Request) GetAuthorizeCodeGeneration() uint64 {
	return a.GetRecoveryGeneration()
}

// SetAuthorizeCodeGeneration sets the authorization-code generation.
func (a *Request) SetAuthorizeCodeGeneration(generation uint64) {
	a.SetRecoveryGeneration(generation)
}

// GetAuthorizationGeneration returns the authorization generation.
func (a *Request) GetAuthorizationGeneration() uint64 {
	return a.GetRecoveryGeneration()
}

// SetAuthorizationGeneration sets the authorization generation.
func (a *Request) SetAuthorizationGeneration(generation uint64) {
	a.SetRecoveryGeneration(generation)
}

// GetCodeGeneration returns the authorization-code generation.
func (a *Request) GetCodeGeneration() uint64 {
	return a.GetRecoveryGeneration()
}

// SetCodeGeneration sets the authorization-code generation.
func (a *Request) SetCodeGeneration(generation uint64) {
	a.SetRecoveryGeneration(generation)
}

// GetAuthorizeCodeStatus returns the authorization-code lifecycle state.
func (a *Request) GetAuthorizeCodeStatus() string {
	if a == nil {
		return ""
	}
	if a.AuthorizeCodeStatus != "" {
		return a.AuthorizeCodeStatus
	}
	if a.AuthorizationCodeStatus != "" {
		return a.AuthorizationCodeStatus
	}
	return a.CodeStatus
}

// SetAuthorizeCodeStatus sets the authorization-code lifecycle state and its
// aliases.
func (a *Request) SetAuthorizeCodeStatus(status string) {
	if a == nil {
		return
	}
	a.AuthorizeCodeStatus = status
	a.AuthorizationCodeStatus = status
	a.CodeStatus = status
}

// GetAuthorizationCodeStatus returns the authorization-code lifecycle state.
func (a *Request) GetAuthorizationCodeStatus() string {
	return a.GetAuthorizeCodeStatus()
}

// SetAuthorizationCodeStatus sets the authorization-code lifecycle state.
func (a *Request) SetAuthorizationCodeStatus(status string) {
	a.SetAuthorizeCodeStatus(status)
}

// GetCodeStatus returns the authorization-code lifecycle state.
func (a *Request) GetCodeStatus() string {
	return a.GetAuthorizeCodeStatus()
}

// SetCodeStatus sets the authorization-code lifecycle state.
func (a *Request) SetCodeStatus(status string) {
	a.SetAuthorizeCodeStatus(status)
}

// GetAuthorizationCodeConsumed reports whether the authorization code has
// been consumed.
func (a *Request) GetAuthorizationCodeConsumed() bool {
	return a.GetAuthorizeCodeStatus() == AuthorizeCodeStatusConsumed
}

// GetCodeConsumed reports whether the authorization code has been consumed.
func (a *Request) GetCodeConsumed() bool {
	return a.GetAuthorizationCodeConsumed()
}

// GetAuthorizeCodeStage returns the last completed authorization-code stage.
func (a *Request) GetAuthorizeCodeStage() string {
	if a == nil {
		return ""
	}
	return a.AuthorizeCodeStage
}

// SetAuthorizeCodeStage sets the last completed authorization-code stage.
func (a *Request) SetAuthorizeCodeStage(stage string) {
	if a != nil {
		a.AuthorizeCodeStage = stage
	}
}

// GetRejectionStage returns the stage that rejected the transaction.
func (a *Request) GetRejectionStage() string {
	if a == nil {
		return ""
	}
	if a.RejectionStage != "" {
		return a.RejectionStage
	}
	return a.FailureStage
}

// SetRejectionStage sets the rejection stage and its alias.
func (a *Request) SetRejectionStage(stage string) {
	if a == nil {
		return
	}
	a.RejectionStage = stage
	a.FailureStage = stage
}

// GetFailureStage returns the stage that rejected the transaction.
func (a *Request) GetFailureStage() string {
	return a.GetRejectionStage()
}

// SetFailureStage sets the stage that rejected the transaction.
func (a *Request) SetFailureStage(stage string) {
	a.SetRejectionStage(stage)
}

// GetAuthorizationRedirectURI returns the redirect URI frozen at the
// authorization endpoint.
func (a *Request) GetAuthorizationRedirectURI() string {
	if a == nil {
		return ""
	}
	return a.AuthorizationRedirectURI
}

// SetAuthorizationRedirectURI sets the redirect URI frozen at the
// authorization endpoint.
func (a *Request) SetAuthorizationRedirectURI(redirectURI string) {
	if a != nil {
		a.AuthorizationRedirectURI = redirectURI
	}
}
