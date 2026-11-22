// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/google/uuid"

	"github.com/ory/fosite"
	"github.com/ory/fosite/internal"
)

type MemoryUserRelation struct {
	Username string
	Password string
}

type IssuerPublicKeys struct {
	Issuer    string
	KeysBySub map[string]SubjectPublicKeys
}

type SubjectPublicKeys struct {
	Subject string
	Keys    map[string]PublicKeyScopes
}

type PublicKeyScopes struct {
	Key    *jose.JSONWebKey
	Scopes []string
}

type DeviceAuthPair struct {
	d string
	u string
}

type MemoryStore struct {
	Clients         map[string]fosite.Client
	AuthorizeCodes  map[string]StoreAuthorizeCode
	IDSessions      map[string]fosite.Requester
	AccessTokens    map[string]fosite.Requester
	RefreshTokens   map[string]StoreRefreshToken
	DeviceAuths     map[string]fosite.DeviceRequester
	PKCES           map[string]fosite.Requester
	Users           map[string]MemoryUserRelation
	BlacklistedJTIs map[string]time.Time
	// In-memory request ID to token signatures
	AccessTokenRequestIDs  map[string]string
	RefreshTokenRequestIDs map[string]string
	// AccessTokenGenerations maps a token signature to its generation within
	// the request ID (token family). AccessTokenGenerationCounters keeps the
	// highest generation ever allocated for a request ID, and
	// AccessTokenRevocationGenerations keeps the highest generation that was
	// revoked. A token is active only when its generation is greater than the
	// revoked generation. These maps are exported so that restart/snapshot
	// implementations preserve the revocation state together with the token
	// sessions.
	AccessTokenGenerations            map[string]uint64
	AccessTokenGenerationCounters     map[string]uint64
	AccessTokenRevocationGenerations  map[string]uint64
	RefreshTokenGenerations           map[string]uint64
	RefreshTokenGenerationCounters    map[string]uint64
	RefreshTokenRevocationGenerations map[string]uint64
	DeviceCodesRequestIDs  map[string]DeviceAuthPair
	UserCodesRequestIDs    map[string]string
	// Public keys to check signature in auth grant jwt assertion.
	IssuerPublicKeys map[string]IssuerPublicKeys
	PARSessions      map[string]fosite.AuthorizeRequester
	// TokenRevocations stores durable revocation evidence keyed by the
	// non-reversible token digest (see fosite.TokenDigest). The state is
	// independent of the token session so that stateless JWT introspection can
	// also observe revocations after a restart.
	TokenRevocations          map[string]fosite.TokenRevocationRecord
	TokenRevocationGeneration uint64
	// RevokedTokenSignatures is the signature-keyed view used by stateless JWT
	// introspection. It allows a token to be recognized as revoked even when no
	// access token session is stored for it.
	RevokedTokenSignatures map[string]time.Time

	clientsMutex                sync.RWMutex
	authorizeCodesMutex         sync.RWMutex
	idSessionsMutex             sync.RWMutex
	accessTokensMutex           sync.RWMutex
	refreshTokensMutex          sync.RWMutex
	deviceAuthsMutex            sync.RWMutex
	pkcesMutex                  sync.RWMutex
	usersMutex                  sync.RWMutex
	blacklistedJTIsMutex        sync.RWMutex
	accessTokenRequestIDsMutex  sync.RWMutex
	refreshTokenRequestIDsMutex sync.RWMutex
	deviceAuthsRequestIDsMutex  sync.RWMutex
	issuerPublicKeysMutex       sync.RWMutex
	parSessionsMutex            sync.RWMutex
	tokenRevocationsMutex       sync.RWMutex
	revokedSignaturesMutex      sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:                make(map[string]fosite.Client),
		AuthorizeCodes:         make(map[string]StoreAuthorizeCode),
		IDSessions:             make(map[string]fosite.Requester),
		AccessTokens:           make(map[string]fosite.Requester),
		RefreshTokens:          make(map[string]StoreRefreshToken),
		DeviceAuths:            make(map[string]fosite.DeviceRequester),
		PKCES:                  make(map[string]fosite.Requester),
		Users:                  make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:  make(map[string]string),
		RefreshTokenRequestIDs: make(map[string]string),
		DeviceCodesRequestIDs:  make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:    make(map[string]string),
		BlacklistedJTIs:        make(map[string]time.Time),
		IssuerPublicKeys:       make(map[string]IssuerPublicKeys),
		PARSessions:            make(map[string]fosite.AuthorizeRequester),
		AccessTokenGenerations:            make(map[string]uint64),
		AccessTokenGenerationCounters:     make(map[string]uint64),
		AccessTokenRevocationGenerations:  make(map[string]uint64),
		RefreshTokenGenerations:           make(map[string]uint64),
		RefreshTokenGenerationCounters:    make(map[string]uint64),
		RefreshTokenRevocationGenerations: make(map[string]uint64),
		TokenRevocations:                  make(map[string]fosite.TokenRevocationRecord),
		RevokedTokenSignatures:            make(map[string]time.Time),
	}
}

var (
	_ fosite.TokenRevocationRecorder          = (*MemoryStore)(nil)
	_ fosite.TokenRevocationChecker           = (*MemoryStore)(nil)
	_ fosite.TokenRevocationStateProvider     = (*MemoryStore)(nil)
	_ fosite.TokenSignatureRevocationRecorder = (*MemoryStore)(nil)
	_ fosite.TokenSignatureRevocationChecker  = (*MemoryStore)(nil)
)

type StoreAuthorizeCode struct {
	active bool
	fosite.Requester
}

type StoreRefreshToken struct {
	active               bool
	// Active is the exported, JSON-persisted mirror of active. It allows a
	// store that is serialized and reloaded during a restart to retain the
	// revocation state of a refresh token.
	Active               bool `json:"active"`
	accessTokenSignature string
	fosite.Requester
}

func NewExampleStore() *MemoryStore {
	return &MemoryStore{
		IDSessions: make(map[string]fosite.Requester),
		Clients: map[string]fosite.Client{
			"my-client": &fosite.DefaultClient{
				ID:             "my-client",
				Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
				RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
			"custom-lifespan-client": &fosite.DefaultClientWithCustomTokenLifespans{
				DefaultClient: &fosite.DefaultClient{
					ID:             "custom-lifespan-client",
					Secret:         []byte(`$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`),            // = "foobar"
					RotatedSecrets: [][]byte{[]byte(`$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC `)}, // = "foobaz",
					RedirectURIs:   []string{"http://localhost:3846/callback"},
					ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
					GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
					Scopes:         []string{"fosite", "openid", "photos", "offline"},
				},
				TokenLifespans: &internal.TestLifespans,
			},
			"encoded:client": &fosite.DefaultClient{
				ID:             "encoded:client",
				Secret:         []byte(`$2a$10$A7M8b65dSSKGHF0H2sNkn.9Z0hT8U1Nv6OWPV3teUUaczXkVkxuDS`), // = "encoded&password"
				RotatedSecrets: nil,
				RedirectURIs:   []string{"http://localhost:3846/callback"},
				ResponseTypes:  []string{"id_token", "code", "token", "id_token token", "code id_token", "code token", "code id_token token"},
				GrantTypes:     []string{"implicit", "refresh_token", "authorization_code", "password", "client_credentials"},
				Scopes:         []string{"fosite", "openid", "photos", "offline"},
			},
		},
		Users: map[string]MemoryUserRelation{
			"peter": {
				// This store simply checks for equality, a real storage implementation would obviously use
				// a hashing algorithm for encrypting the user password.
				Username: "peter",
				Password: "secret",
			},
		},
		AuthorizeCodes:         map[string]StoreAuthorizeCode{},
		AccessTokens:           map[string]fosite.Requester{},
		RefreshTokens:          map[string]StoreRefreshToken{},
		PKCES:                  map[string]fosite.Requester{},
		DeviceAuths:            make(map[string]fosite.DeviceRequester),
		AccessTokenRequestIDs:  map[string]string{},
		RefreshTokenRequestIDs: map[string]string{},
		DeviceCodesRequestIDs:  make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:    make(map[string]string),
		IssuerPublicKeys:       map[string]IssuerPublicKeys{},
		PARSessions:            map[string]fosite.AuthorizeRequester{},
		AccessTokenGenerations:            map[string]uint64{},
		AccessTokenGenerationCounters:     map[string]uint64{},
		AccessTokenRevocationGenerations:  map[string]uint64{},
		RefreshTokenGenerations:           map[string]uint64{},
		RefreshTokenGenerationCounters:    map[string]uint64{},
		RefreshTokenRevocationGenerations: map[string]uint64{},
		TokenRevocations:                  map[string]fosite.TokenRevocationRecord{},
		RevokedTokenSignatures:            map[string]time.Time{},
	}
}

func (s *MemoryStore) CreateOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	s.IDSessions[authorizeCode] = requester
	return nil
}

func (s *MemoryStore) GetOpenIDConnectSession(_ context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	s.idSessionsMutex.RLock()
	defer s.idSessionsMutex.RUnlock()

	cl, ok := s.IDSessions[authorizeCode]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) DeleteOpenIDConnectSession(_ context.Context, authorizeCode string) error {
	s.idSessionsMutex.Lock()
	defer s.idSessionsMutex.Unlock()

	delete(s.IDSessions, authorizeCode)
	return nil
}

func (s *MemoryStore) GetClient(_ context.Context, id string) (fosite.Client, error) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	cl, ok := s.Clients[id]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return cl, nil
}

func (s *MemoryStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	if client, ok := s.Clients[clientID]; ok {
		if clc, ok := client.(*fosite.DefaultClientWithCustomTokenLifespans); ok {
			clc.SetTokenLifespans(lifespans)
			return nil
		}
		return fosite.ErrorToRFC6749Error(errors.New("failed to set token lifespans due to failed client type assertion"))
	}
	return fosite.ErrNotFound
}

func (s *MemoryStore) ClientAssertionJWTValid(_ context.Context, jti string) error {
	s.blacklistedJTIsMutex.RLock()
	defer s.blacklistedJTIsMutex.RUnlock()

	if exp, exists := s.BlacklistedJTIs[jti]; exists && exp.After(time.Now()) {
		return fosite.ErrJTIKnown
	}

	return nil
}

func (s *MemoryStore) SetClientAssertionJWT(_ context.Context, jti string, exp time.Time) error {
	s.blacklistedJTIsMutex.Lock()
	defer s.blacklistedJTIsMutex.Unlock()

	// delete expired jtis
	for j, e := range s.BlacklistedJTIs {
		if e.Before(time.Now()) {
			delete(s.BlacklistedJTIs, j)
		}
	}

	if _, exists := s.BlacklistedJTIs[jti]; exists {
		return fosite.ErrJTIKnown
	}

	s.BlacklistedJTIs[jti] = exp
	return nil
}

func (s *MemoryStore) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	s.AuthorizeCodes[code] = StoreAuthorizeCode{active: true, Requester: req}
	return nil
}

func (s *MemoryStore) GetAuthorizeCodeSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.authorizeCodesMutex.RLock()
	defer s.authorizeCodesMutex.RUnlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active {
		return rel, fosite.ErrInvalidatedAuthorizeCode
	}

	return rel.Requester, nil
}

func (s *MemoryStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	s.authorizeCodesMutex.Lock()
	defer s.authorizeCodesMutex.Unlock()

	rel, ok := s.AuthorizeCodes[code]
	if !ok {
		return fosite.ErrNotFound
	}
	rel.active = false
	s.AuthorizeCodes[code] = rel
	return nil
}

func (s *MemoryStore) CreatePKCERequestSession(_ context.Context, code string, req fosite.Requester) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	s.PKCES[code] = req
	return nil
}

func (s *MemoryStore) GetPKCERequestSession(_ context.Context, code string, _ fosite.Session) (fosite.Requester, error) {
	s.pkcesMutex.RLock()
	defer s.pkcesMutex.RUnlock()

	rel, ok := s.PKCES[code]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

func (s *MemoryStore) DeletePKCERequestSession(_ context.Context, code string) error {
	s.pkcesMutex.Lock()
	defer s.pkcesMutex.Unlock()

	delete(s.PKCES, code)
	return nil
}

func (s *MemoryStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	// We first lock accessTokenRequestIDsMutex and then accessTokensMutex because this is the same order
	// locking happens in RevokeAccessToken and using the same order prevents deadlocks.
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	if s.AccessTokens == nil {
		s.AccessTokens = make(map[string]fosite.Requester)
	}
	if s.AccessTokenRequestIDs == nil {
		s.AccessTokenRequestIDs = make(map[string]string)
	}
	if s.AccessTokenGenerations == nil {
		s.AccessTokenGenerations = make(map[string]uint64)
	}
	if s.AccessTokenGenerationCounters == nil {
		s.AccessTokenGenerationCounters = make(map[string]uint64)
	}
	if s.AccessTokenRevocationGenerations == nil {
		s.AccessTokenRevocationGenerations = make(map[string]uint64)
	}

	requestID := req.GetID()
	nextGeneration := s.AccessTokenGenerationCounters[requestID] + 1
	if revoked := s.AccessTokenRevocationGenerations[requestID]; nextGeneration <= revoked {
		nextGeneration = revoked + 1
	}

	// Only the latest access token generation of a request (token family) may
	// stay active. Older generations are removed so that a retry, concurrent
	// rotation, or a storage rollback cannot leave a second usable token
	// behind.
	if previousSignature, ok := s.AccessTokenRequestIDs[requestID]; ok && previousSignature != signature {
		if previous, exists := s.AccessTokens[previousSignature]; exists {
			delete(s.AccessTokens, previousSignature)
			delete(s.AccessTokenGenerations, previousSignature)
			_ = s.RecordTokenSignatureRevocation(ctx, previousSignature, tokenExpiry(previous, fosite.AccessToken))
		}
	}
	for previousSignature, previous := range s.AccessTokens {
		if previousSignature == signature || previous == nil {
			continue
		}
		if requesterID(previous) == requestID {
			delete(s.AccessTokens, previousSignature)
			delete(s.AccessTokenGenerations, previousSignature)
			_ = s.RecordTokenSignatureRevocation(ctx, previousSignature, tokenExpiry(previous, fosite.AccessToken))
		}
	}

	s.AccessTokenGenerations[signature] = nextGeneration
	s.AccessTokenGenerationCounters[requestID] = nextGeneration
	if nextGeneration > 0 {
		s.AccessTokenRevocationGenerations[requestID] = nextGeneration - 1
	}
	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[requestID] = signature
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.accessTokensMutex.RLock()
	defer s.accessTokensMutex.RUnlock()

	rel, ok := s.AccessTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if rel == nil {
		return nil, fosite.ErrNotFound
	}
	requestID := requesterID(rel)
	generation := s.AccessTokenGenerations[signature]
	if revoked := s.AccessTokenRevocationGenerations[requestID]; revoked > 0 && generation <= revoked {
		return rel, fosite.ErrInactiveToken
	}
	revoked, err := s.IsTokenSignatureRevoked(ctx, signature)
	if err != nil {
		return rel, err
	}
	if revoked {
		return rel, fosite.ErrInactiveToken
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	expiresAt := time.Time{}
	if request, ok := s.AccessTokens[signature]; ok {
		expiresAt = tokenExpiry(request, fosite.AccessToken)
	}
	delete(s.AccessTokens, signature)
	delete(s.AccessTokenGenerations, signature)
	for requestID, tokenSignature := range s.AccessTokenRequestIDs {
		if tokenSignature == signature {
			delete(s.AccessTokenRequestIDs, requestID)
		}
	}
	_ = s.RecordTokenSignatureRevocation(ctx, signature, expiresAt)
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in RevokeRefreshToken and using the same order prevents deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	if s.RefreshTokens == nil {
		s.RefreshTokens = make(map[string]StoreRefreshToken)
	}
	if s.RefreshTokenRequestIDs == nil {
		s.RefreshTokenRequestIDs = make(map[string]string)
	}
	if s.RefreshTokenGenerations == nil {
		s.RefreshTokenGenerations = make(map[string]uint64)
	}
	if s.RefreshTokenGenerationCounters == nil {
		s.RefreshTokenGenerationCounters = make(map[string]uint64)
	}
	if s.RefreshTokenRevocationGenerations == nil {
		s.RefreshTokenRevocationGenerations = make(map[string]uint64)
	}

	requestID := req.GetID()
	nextGeneration := s.RefreshTokenGenerationCounters[requestID] + 1
	if revoked := s.RefreshTokenRevocationGenerations[requestID]; nextGeneration <= revoked {
		nextGeneration = revoked + 1
	}

	// Keep the previous generations as inactive tombstones. Refresh token
	// reuse detection relies on getting ErrInactiveToken (rather than
	// ErrNotFound) for an already rotated token.
	if previousSignature, ok := s.RefreshTokenRequestIDs[requestID]; ok && previousSignature != signature {
		if previous, exists := s.RefreshTokens[previousSignature]; exists {
			previous.active = false
			previous.Active = false
			s.RefreshTokens[previousSignature] = previous
			_ = s.RecordTokenSignatureRevocation(ctx, previousSignature, tokenExpiry(previous.Requester, fosite.RefreshToken))
		}
	}
	for previousSignature, previous := range s.RefreshTokens {
		if previousSignature == signature || previous.Requester == nil {
			continue
		}
		if requesterID(previous.Requester) == requestID {
			previous.active = false
			previous.Active = false
			s.RefreshTokens[previousSignature] = previous
			_ = s.RecordTokenSignatureRevocation(ctx, previousSignature, tokenExpiry(previous.Requester, fosite.RefreshToken))
		}
	}

	s.RefreshTokenGenerations[signature] = nextGeneration
	s.RefreshTokenGenerationCounters[requestID] = nextGeneration
	if nextGeneration > 0 {
		s.RefreshTokenRevocationGenerations[requestID] = nextGeneration - 1
	}
	s.RefreshTokens[signature] = StoreRefreshToken{
		active:               true,
		Active:               true,
		Requester:            req,
		accessTokenSignature: accessTokenSignature,
	}
	s.RefreshTokenRequestIDs[requestID] = signature
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.refreshTokensMutex.RLock()
	defer s.refreshTokensMutex.RUnlock()

	rel, ok := s.RefreshTokens[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if rel.Requester == nil {
		return nil, fosite.ErrNotFound
	}
	if !rel.active && !rel.Active {
		return rel, fosite.ErrInactiveToken
	}
	requestID := requesterID(rel)
	if revoked := s.RefreshTokenRevocationGenerations[requestID]; revoked > 0 {
		if generation := s.RefreshTokenGenerations[signature]; generation <= revoked {
			return rel, fosite.ErrInactiveToken
		}
	}
	revoked, err := s.IsTokenSignatureRevoked(ctx, signature)
	if err != nil {
		return rel, err
	}
	if revoked {
		return rel, fosite.ErrInactiveToken
	}
	return rel, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	expiresAt := time.Time{}
	if request, ok := s.RefreshTokens[signature]; ok {
		expiresAt = tokenExpiry(request.Requester, fosite.RefreshToken)
	}
	delete(s.RefreshTokens, signature)
	delete(s.RefreshTokenGenerations, signature)
	for requestID, tokenSignature := range s.RefreshTokenRequestIDs {
		if tokenSignature == signature {
			delete(s.RefreshTokenRequestIDs, requestID)
		}
	}
	_ = s.RecordTokenSignatureRevocation(ctx, signature, expiresAt)
	return nil
}

func (s *MemoryStore) Authenticate(_ context.Context, name string, secret string) (subject string, err error) {
	s.usersMutex.RLock()
	defer s.usersMutex.RUnlock()

	rel, ok := s.Users[name]
	if !ok {
		return "", fosite.ErrNotFound
	}
	if rel.Password != secret {
		return "", fosite.ErrNotFound.WithDebug("Invalid credentials")
	}
	return uuid.New().String(), nil
}

func (s *MemoryStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in CreateRefreshTokenSession and using the same order prevents deadlocks.
	revokedSignatures := make(map[string]time.Time)

	func() {
		s.refreshTokenRequestIDsMutex.Lock()
		defer s.refreshTokenRequestIDsMutex.Unlock()
		s.refreshTokensMutex.Lock()
		defer s.refreshTokensMutex.Unlock()

		if s.RefreshTokens == nil {
			s.RefreshTokens = make(map[string]StoreRefreshToken)
		}
		if s.RefreshTokenGenerations == nil {
			s.RefreshTokenGenerations = make(map[string]uint64)
		}
		if s.RefreshTokenGenerationCounters == nil {
			s.RefreshTokenGenerationCounters = make(map[string]uint64)
		}
		if s.RefreshTokenRevocationGenerations == nil {
			s.RefreshTokenRevocationGenerations = make(map[string]uint64)
		}

		generation := s.RefreshTokenGenerationCounters[requestID]
		matched := false
		if signature, ok := s.RefreshTokenRequestIDs[requestID]; ok {
			matched = true
			if request, exists := s.RefreshTokens[signature]; exists {
				if tokenGeneration := s.RefreshTokenGenerations[signature]; tokenGeneration > generation {
					generation = tokenGeneration
				}
				if expiresAt := tokenExpiry(request.Requester, fosite.RefreshToken); !expiresAt.IsZero() {
					revokedSignatures[signature] = expiresAt
				}
				request.active = false
				request.Active = false
				s.RefreshTokens[signature] = request
			}
		}
		for signature, request := range s.RefreshTokens {
			if request.Requester == nil || requesterID(request.Requester) != requestID {
				continue
			}
			matched = true
			if tokenGeneration := s.RefreshTokenGenerations[signature]; tokenGeneration > generation {
				generation = tokenGeneration
			}
			if expiresAt := tokenExpiry(request.Requester, fosite.RefreshToken); !expiresAt.IsZero() {
				revokedSignatures[signature] = expiresAt
			}
			request.active = false
			request.Active = false
			s.RefreshTokens[signature] = request
		}
		if !matched && generation == 0 {
			return
		}
		if generation == 0 {
			generation = 1
		}
		if previous := s.RefreshTokenRevocationGenerations[requestID]; generation > previous {
			s.RefreshTokenRevocationGenerations[requestID] = generation
		}
	}()

	for signature, expiresAt := range revokedSignatures {
		_ = s.RecordTokenSignatureRevocation(ctx, signature, expiresAt)
	}
	return nil
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	revokedSignatures := make(map[string]time.Time)

	func() {
		s.accessTokenRequestIDsMutex.Lock()
		defer s.accessTokenRequestIDsMutex.Unlock()
		s.accessTokensMutex.Lock()
		defer s.accessTokensMutex.Unlock()

		if s.AccessTokens == nil {
			s.AccessTokens = make(map[string]fosite.Requester)
		}
		if s.AccessTokenGenerations == nil {
			s.AccessTokenGenerations = make(map[string]uint64)
		}
		if s.AccessTokenGenerationCounters == nil {
			s.AccessTokenGenerationCounters = make(map[string]uint64)
		}
		if s.AccessTokenRevocationGenerations == nil {
			s.AccessTokenRevocationGenerations = make(map[string]uint64)
		}

		generation := s.AccessTokenGenerationCounters[requestID]
		matched := false
		if signature, ok := s.AccessTokenRequestIDs[requestID]; ok {
			matched = true
			if request, exists := s.AccessTokens[signature]; exists {
				if tokenGeneration := s.AccessTokenGenerations[signature]; tokenGeneration > generation {
					generation = tokenGeneration
				}
				if expiresAt := tokenExpiry(request, fosite.AccessToken); !expiresAt.IsZero() {
					revokedSignatures[signature] = expiresAt
				}
				delete(s.AccessTokens, signature)
				delete(s.AccessTokenGenerations, signature)
			}
		}
		for signature, request := range s.AccessTokens {
			if request == nil || requesterID(request) != requestID {
				continue
			}
			matched = true
			if tokenGeneration := s.AccessTokenGenerations[signature]; tokenGeneration > generation {
				generation = tokenGeneration
			}
			if expiresAt := tokenExpiry(request, fosite.AccessToken); !expiresAt.IsZero() {
				revokedSignatures[signature] = expiresAt
			}
			delete(s.AccessTokens, signature)
			delete(s.AccessTokenGenerations, signature)
		}
		if !matched && generation == 0 {
			return
		}
		if generation == 0 {
			generation = 1
		}
		if previous := s.AccessTokenRevocationGenerations[requestID]; generation > previous {
			s.AccessTokenRevocationGenerations[requestID] = generation
		}
	}()

	for signature, expiresAt := range revokedSignatures {
		_ = s.RecordTokenSignatureRevocation(ctx, signature, expiresAt)
	}
	return nil
}

func tokenExpiry(request fosite.Requester, tokenType fosite.TokenType) time.Time {
	if request == nil {
		return time.Time{}
	}
	session := request.GetSession()
	if session == nil {
		return time.Time{}
	}
	return session.GetExpiresAt(tokenType)
}

func requesterID(request fosite.Requester) string {
	if request == nil {
		return ""
	}
	if typed, ok := request.(*fosite.Request); ok {
		return typed.ID
	}
	return request.GetID()
}

// RecordTokenRevocation stores durable revocation evidence for a token
// digest. Re-recording the same digest is idempotent and keeps the original
// generation and revocation timestamp so that retries cannot make a revoked
// token active again or move the revocation generation forward.
func (s *MemoryStore) RecordTokenRevocation(_ context.Context, record fosite.TokenRevocationRecord) error {
	if record.TokenDigest == "" {
		return nil
	}

	if record.RevocationGeneration == 0 {
		record.RevocationGeneration = s.currentRevocationGeneration(record)
	}

	s.tokenRevocationsMutex.Lock()
	defer s.tokenRevocationsMutex.Unlock()

	if s.TokenRevocations == nil {
		s.TokenRevocations = make(map[string]fosite.TokenRevocationRecord)
	}
	if existing, ok := s.TokenRevocations[record.TokenDigest]; ok {
		if record.RevocationGeneration > existing.RevocationGeneration {
			existing.RevocationGeneration = record.RevocationGeneration
		}
		if existing.TokenSignature == "" {
			existing.TokenSignature = record.TokenSignature
		}
		if existing.TokenUse == "" {
			existing.TokenUse = record.TokenUse
		}
		if existing.ClientID == "" {
			existing.ClientID = record.ClientID
		}
		if existing.RequestID == "" {
			existing.RequestID = record.RequestID
		}
		if existing.Source == "" {
			existing.Source = record.Source
		}
		if existing.ExpiresAt.IsZero() {
			existing.ExpiresAt = record.ExpiresAt
		}
		s.TokenRevocations[record.TokenDigest] = existing
		return nil
	}

	s.TokenRevocationGeneration++
	record.Generation = s.TokenRevocationGeneration
	if record.RevocationGeneration == 0 {
		record.RevocationGeneration = record.Generation
	}
	if record.RevokedAt.IsZero() {
		record.RevokedAt = time.Now().UTC()
	}
	s.TokenRevocations[record.TokenDigest] = record
	return nil
}

func (s *MemoryStore) currentRevocationGeneration(record fosite.TokenRevocationRecord) uint64 {
	if record.RequestID == "" {
		return 0
	}
	switch record.TokenUse {
	case fosite.AccessToken:
		s.accessTokensMutex.RLock()
		defer s.accessTokensMutex.RUnlock()
		return s.AccessTokenRevocationGenerations[record.RequestID]
	case fosite.RefreshToken:
		s.refreshTokensMutex.RLock()
		defer s.refreshTokensMutex.RUnlock()
		return s.RefreshTokenRevocationGenerations[record.RequestID]
	default:
		return 0
	}
}

// GetTokenRevocationState returns the durable revocation evidence for a token
// digest. It is used by introspection reports and returns ErrNotFound when the
// token has not been revoked.
func (s *MemoryStore) GetTokenRevocationState(_ context.Context, tokenDigest string) (fosite.TokenRevocationRecord, error) {
	s.tokenRevocationsMutex.RLock()
	defer s.tokenRevocationsMutex.RUnlock()

	record, ok := s.TokenRevocations[tokenDigest]
	if !ok {
		return fosite.TokenRevocationRecord{}, fosite.ErrNotFound
	}
	return record, nil
}

// IsTokenRevoked reports whether the given token digest has durable
// revocation evidence. Expired evidence is removed lazily.
func (s *MemoryStore) IsTokenRevoked(_ context.Context, tokenDigest string) (bool, error) {
	s.tokenRevocationsMutex.RLock()
	record, ok := s.TokenRevocations[tokenDigest]
	s.tokenRevocationsMutex.RUnlock()
	if !ok {
		return false, nil
	}
	if !record.ExpiresAt.IsZero() && !time.Now().UTC().Before(record.ExpiresAt) {
		s.tokenRevocationsMutex.Lock()
		delete(s.TokenRevocations, tokenDigest)
		s.tokenRevocationsMutex.Unlock()
		return false, nil
	}
	return true, nil
}

// RecordTokenSignatureRevocation stores a signature-keyed revocation marker.
// Stateless JWT introspection uses this marker, because it deliberately does
// not load access token sessions.
func (s *MemoryStore) RecordTokenSignatureRevocation(_ context.Context, signature string, expiresAt time.Time) error {
	if signature == "" {
		return nil
	}

	s.revokedSignaturesMutex.Lock()
	defer s.revokedSignaturesMutex.Unlock()

	if s.RevokedTokenSignatures == nil {
		s.RevokedTokenSignatures = make(map[string]time.Time)
	}
	if existing, ok := s.RevokedTokenSignatures[signature]; ok {
		if existing.IsZero() || expiresAt.IsZero() {
			s.RevokedTokenSignatures[signature] = time.Time{}
			return nil
		}
		if expiresAt.After(existing) {
			s.RevokedTokenSignatures[signature] = expiresAt
		}
		return nil
	}
	s.RevokedTokenSignatures[signature] = expiresAt
	return nil
}

// IsTokenSignatureRevoked reports whether a token signature has been revoked.
// Expired markers are removed lazily.
func (s *MemoryStore) IsTokenSignatureRevoked(_ context.Context, signature string) (bool, error) {
	s.revokedSignaturesMutex.RLock()
	expiresAt, ok := s.RevokedTokenSignatures[signature]
	s.revokedSignaturesMutex.RUnlock()
	if !ok {
		return false, nil
	}
	if !expiresAt.IsZero() && !time.Now().UTC().Before(expiresAt) {
		s.revokedSignaturesMutex.Lock()
		delete(s.RevokedTokenSignatures, signature)
		s.revokedSignaturesMutex.Unlock()
		return false, nil
	}
	return true, nil
}

func (s *MemoryStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Key, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if len(subKeys.Keys) == 0 {
				return nil, fosite.ErrNotFound
			}

			keys := make([]jose.JSONWebKey, 0, len(subKeys.Keys))
			for _, keyScopes := range subKeys.Keys {
				keys = append(keys, *keyScopes.Key)
			}

			return &jose.JSONWebKeySet{Keys: keys}, nil
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	s.issuerPublicKeysMutex.RLock()
	defer s.issuerPublicKeysMutex.RUnlock()

	if issuerKeys, ok := s.IssuerPublicKeys[issuer]; ok {
		if subKeys, ok := issuerKeys.KeysBySub[subject]; ok {
			if keyScopes, ok := subKeys.Keys[keyId]; ok {
				return keyScopes.Scopes, nil
			}
		}
	}

	return nil, fosite.ErrNotFound
}

func (s *MemoryStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	err := s.ClientAssertionJWTValid(ctx, jti)
	if err != nil {
		return true, nil
	}

	return false, nil
}

func (s *MemoryStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return s.SetClientAssertionJWT(ctx, jti, exp)
}

// CreatePARSession stores the pushed authorization request context. The requestURI is used to derive the key.
func (s *MemoryStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	s.PARSessions[requestURI] = request
	return nil
}

// GetPARSession gets the push authorization request context. If the request is nil, a new request object
// is created. Otherwise, the same object is updated.
func (s *MemoryStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	s.parSessionsMutex.RLock()
	defer s.parSessionsMutex.RUnlock()

	r, ok := s.PARSessions[requestURI]
	if !ok {
		return nil, fosite.ErrNotFound
	}

	return r, nil
}

// DeletePARSession deletes the context.
func (s *MemoryStore) DeletePARSession(ctx context.Context, requestURI string) (err error) {
	s.parSessionsMutex.Lock()
	defer s.parSessionsMutex.Unlock()

	delete(s.PARSessions, requestURI)
	return nil
}

func (s *MemoryStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) (err error) {
	// Graceful token rotation can be implemented here but it's beyond the scope of this example. Check
	// the Ory Hydra implementation for reference.
	if err := s.RevokeRefreshToken(ctx, requestID); err != nil {
		return err
	}
	return s.RevokeAccessToken(ctx, requestID)
}

// CreateDeviceAuthSession stores the device auth session
func (s *MemoryStore) CreateDeviceAuthSession(_ context.Context, deviceCodeSignature, userCodeSignature string, req fosite.DeviceRequester) error {
	s.deviceAuthsRequestIDsMutex.Lock()
	defer s.deviceAuthsRequestIDsMutex.Unlock()
	s.deviceAuthsMutex.Lock()
	defer s.deviceAuthsMutex.Unlock()

	s.DeviceAuths[deviceCodeSignature] = req
	s.DeviceAuths[userCodeSignature] = req
	s.DeviceCodesRequestIDs[req.GetID()] = DeviceAuthPair{d: deviceCodeSignature, u: userCodeSignature}
	return nil
}

// GetDeviceCodeSession gets the device code session
func (s *MemoryStore) GetDeviceCodeSession(_ context.Context, signature string, _ fosite.Session) (fosite.DeviceRequester, error) {
	s.deviceAuthsMutex.RLock()
	defer s.deviceAuthsMutex.RUnlock()

	rel, ok := s.DeviceAuths[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	return rel, nil
}

// InvalidateDeviceCodeSession invalidates the device code session
func (s *MemoryStore) InvalidateDeviceCodeSession(_ context.Context, code string) error {
	s.deviceAuthsMutex.Lock()
	defer s.deviceAuthsMutex.Unlock()

	delete(s.DeviceAuths, code)
	return nil
}
