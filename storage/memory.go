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
	// Token family revocation tombstones. They are keyed by the request ID
	// shared by an access token and its refresh token chain. Keeping the
	// tombstone separately from the token sessions makes a partial cleanup
	// fail closed: even if a token session is still present, every consumer
	// sees the family as revoked.
	RevokedTokenFamilies         map[string]fosite.TokenFamilyRevocationRecord
	TokenFamilyRevocationCounter uint64
	// Generation maps track the latest access/refresh token generation for a
	// request family. They are exported so that snapshot/restart
	// implementations preserve the generation together with the sessions.
	AccessTokenGenerations            map[string]uint64
	AccessTokenGenerationCounters     map[string]uint64
	AccessTokenRevocationGenerations  map[string]uint64
	RefreshTokenGenerations           map[string]uint64
	RefreshTokenGenerationCounters    map[string]uint64
	RefreshTokenRevocationGenerations map[string]uint64
	// Token signature to request-family indexes. They are intentionally kept
	// after a token session is rotated out, so revocation can still identify
	// the family from a token that a concurrent refresh already consumed.
	AccessTokenFamilies  map[string]string
	RefreshTokenFamilies map[string]string
	TokenFamilyClients   map[string]string
	// TokenRevocations stores durable revocation evidence keyed by the
	// non-reversible token digest (see fosite.TokenDigest).
	TokenRevocations map[string]fosite.TokenRevocationRecord
	// TokenRevocationGeneration is a monotonically increasing sequence for
	// durable revocation records.
	TokenRevocationGeneration uint64
	// RevokedTokenSignatures is the signature-keyed revocation view used by
	// introspection implementations that do not load token sessions.
	RevokedTokenSignatures map[string]time.Time
	// TokenFamilyBySignature maps a revoked token signature back to its
	// request family, which lets audit consumers correlate evidence after the
	// token session itself has been deleted.
	TokenFamilyBySignature map[string]string
	DeviceCodesRequestIDs  map[string]DeviceAuthPair
	UserCodesRequestIDs    map[string]string
	// Public keys to check signature in auth grant jwt assertion.
	IssuerPublicKeys map[string]IssuerPublicKeys
	PARSessions      map[string]fosite.AuthorizeRequester

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
	tokenFamiliesMutex          sync.RWMutex
	tokenGenerationsMutex       sync.RWMutex
	tokenRevocationsMutex       sync.RWMutex
	revokedSignaturesMutex      sync.RWMutex
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		Clients:                           make(map[string]fosite.Client),
		AuthorizeCodes:                    make(map[string]StoreAuthorizeCode),
		IDSessions:                        make(map[string]fosite.Requester),
		AccessTokens:                      make(map[string]fosite.Requester),
		RefreshTokens:                     make(map[string]StoreRefreshToken),
		DeviceAuths:                       make(map[string]fosite.DeviceRequester),
		PKCES:                             make(map[string]fosite.Requester),
		Users:                             make(map[string]MemoryUserRelation),
		AccessTokenRequestIDs:             make(map[string]string),
		RefreshTokenRequestIDs:            make(map[string]string),
		RevokedTokenFamilies:              make(map[string]fosite.TokenFamilyRevocationRecord),
		AccessTokenGenerations:            make(map[string]uint64),
		AccessTokenGenerationCounters:     make(map[string]uint64),
		AccessTokenRevocationGenerations:  make(map[string]uint64),
		RefreshTokenGenerations:           make(map[string]uint64),
		RefreshTokenGenerationCounters:    make(map[string]uint64),
		RefreshTokenRevocationGenerations: make(map[string]uint64),
		AccessTokenFamilies:               make(map[string]string),
		RefreshTokenFamilies:              make(map[string]string),
		TokenFamilyClients:                make(map[string]string),
		TokenRevocations:                  make(map[string]fosite.TokenRevocationRecord),
		RevokedTokenSignatures:            make(map[string]time.Time),
		TokenFamilyBySignature:            make(map[string]string),
		DeviceCodesRequestIDs:             make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:               make(map[string]string),
		BlacklistedJTIs:                   make(map[string]time.Time),
		IssuerPublicKeys:                  make(map[string]IssuerPublicKeys),
		PARSessions:                       make(map[string]fosite.AuthorizeRequester),
	}
}

type StoreAuthorizeCode struct {
	active bool
	fosite.Requester
}

type StoreRefreshToken struct {
	active bool
	// Active is the exported mirror of active. It keeps the revocation state
	// intact when a store is serialized and restored, for example during a
	// restart.
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
		AuthorizeCodes:                    map[string]StoreAuthorizeCode{},
		AccessTokens:                      map[string]fosite.Requester{},
		RefreshTokens:                     map[string]StoreRefreshToken{},
		PKCES:                             map[string]fosite.Requester{},
		DeviceAuths:                       make(map[string]fosite.DeviceRequester),
		AccessTokenRequestIDs:             map[string]string{},
		RefreshTokenRequestIDs:            map[string]string{},
		RevokedTokenFamilies:              map[string]fosite.TokenFamilyRevocationRecord{},
		AccessTokenGenerations:            map[string]uint64{},
		AccessTokenGenerationCounters:     map[string]uint64{},
		AccessTokenRevocationGenerations:  map[string]uint64{},
		RefreshTokenGenerations:           map[string]uint64{},
		RefreshTokenGenerationCounters:    map[string]uint64{},
		RefreshTokenRevocationGenerations: map[string]uint64{},
		AccessTokenFamilies:               map[string]string{},
		RefreshTokenFamilies:              map[string]string{},
		TokenFamilyClients:                map[string]string{},
		TokenRevocations:                  map[string]fosite.TokenRevocationRecord{},
		RevokedTokenSignatures:            map[string]time.Time{},
		TokenFamilyBySignature:            map[string]string{},
		DeviceCodesRequestIDs:             make(map[string]DeviceAuthPair),
		UserCodesRequestIDs:               make(map[string]string),
		IssuerPublicKeys:                  map[string]IssuerPublicKeys{},
		PARSessions:                       map[string]fosite.AuthorizeRequester{},
	}
}

var (
	_ fosite.TokenFamilyRevocationStorage       = (*MemoryStore)(nil)
	_ fosite.TokenFamilyRevocationStateProvider = (*MemoryStore)(nil)
	_ fosite.TokenFamilyRevocationRecorder      = (*MemoryStore)(nil)
	_ fosite.TokenFamilyResolver                = (*MemoryStore)(nil)
	_ fosite.TokenRevocationRecorder            = (*MemoryStore)(nil)
	_ fosite.TokenRevocationChecker             = (*MemoryStore)(nil)
	_ fosite.TokenRevocationStateProvider       = (*MemoryStore)(nil)
	_ fosite.TokenSignatureRevocationRecorder   = (*MemoryStore)(nil)
	_ fosite.TokenSignatureRevocationChecker    = (*MemoryStore)(nil)
)

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
	requestID := familyIDOf(req)

	// The family lock is acquired before the token map locks. Every method
	// that needs the family tombstone and a token map uses this order, which
	// prevents a revocation from interleaving with token creation.
	s.tokenFamiliesMutex.RLock()
	defer s.tokenFamiliesMutex.RUnlock()

	if requestID != "" {
		if _, revoked := s.RevokedTokenFamilies[requestID]; revoked {
			return fosite.ErrInactiveToken
		}
		s.tokenGenerationsMutex.RLock()
		accessRevoked := s.AccessTokenRevocationGenerations[requestID] > 0
		refreshRevoked := s.RefreshTokenRevocationGenerations[requestID] > 0
		s.tokenGenerationsMutex.RUnlock()
		if accessRevoked || refreshRevoked {
			return fosite.ErrInactiveToken
		}
		s.accessTokenRequestIDsMutex.RLock()
		accessMarker, accessExists := s.AccessTokenRequestIDs[requestID]
		s.accessTokenRequestIDsMutex.RUnlock()
		s.refreshTokenRequestIDsMutex.RLock()
		refreshMarker, refreshExists := s.RefreshTokenRequestIDs[requestID]
		s.refreshTokenRequestIDsMutex.RUnlock()
		if (accessExists && accessMarker == "") || (refreshExists && refreshMarker == "") {
			return fosite.ErrInactiveToken
		}
	}

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
	if marker, exists := s.AccessTokenRequestIDs[requestID]; exists && marker == "" && requestID != "" {
		return fosite.ErrInactiveToken
	}

	s.tokenGenerationsMutex.Lock()
	if s.AccessTokenGenerations == nil {
		s.AccessTokenGenerations = make(map[string]uint64)
	}
	if s.AccessTokenGenerationCounters == nil {
		s.AccessTokenGenerationCounters = make(map[string]uint64)
	}
	if s.AccessTokenRevocationGenerations == nil {
		s.AccessTokenRevocationGenerations = make(map[string]uint64)
	}
	if s.AccessTokenFamilies == nil {
		s.AccessTokenFamilies = make(map[string]string)
	}
	if s.TokenFamilyClients == nil {
		s.TokenFamilyClients = make(map[string]string)
	}
	nextGeneration := s.AccessTokenGenerationCounters[requestID] + 1
	if revoked := s.AccessTokenRevocationGenerations[requestID]; revoked > 0 {
		s.tokenGenerationsMutex.Unlock()
		return fosite.ErrInactiveToken
	}
	s.AccessTokenGenerations[signature] = nextGeneration
	s.AccessTokenGenerationCounters[requestID] = nextGeneration
	s.AccessTokenFamilies[signature] = requestID
	if req != nil && req.GetClient() != nil && req.GetClient().GetID() != "" {
		s.TokenFamilyClients[requestID] = req.GetClient().GetID()
	}
	s.tokenGenerationsMutex.Unlock()

	s.AccessTokens[signature] = req
	s.AccessTokenRequestIDs[requestID] = signature
	return nil
}

func (s *MemoryStore) GetAccessTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.accessTokensMutex.RLock()
	rel, ok := s.AccessTokens[signature]
	s.accessTokensMutex.RUnlock()
	if !ok {
		return nil, fosite.ErrNotFound
	}

	if requestID := familyIDOf(rel); requestID != "" {
		s.tokenFamiliesMutex.RLock()
		_, revoked := s.RevokedTokenFamilies[requestID]
		s.tokenFamiliesMutex.RUnlock()
		s.tokenGenerationsMutex.RLock()
		revocationGeneration := s.AccessTokenRevocationGenerations[requestID]
		generation := s.AccessTokenGenerations[signature]
		s.tokenGenerationsMutex.RUnlock()
		if revoked || (revocationGeneration > 0 && generation <= revocationGeneration) {
			return rel, fosite.ErrInactiveToken
		}
		s.accessTokenRequestIDsMutex.RLock()
		marker, markerExists := s.AccessTokenRequestIDs[requestID]
		s.accessTokenRequestIDsMutex.RUnlock()
		if markerExists && marker == "" {
			return rel, fosite.ErrInactiveToken
		}
		s.refreshTokenRequestIDsMutex.RLock()
		refreshMarker, refreshMarkerExists := s.RefreshTokenRequestIDs[requestID]
		s.refreshTokenRequestIDsMutex.RUnlock()
		if refreshMarkerExists && refreshMarker == "" {
			return rel, fosite.ErrInactiveToken
		}
	}
	return rel, nil
}

func (s *MemoryStore) DeleteAccessTokenSession(_ context.Context, signature string) error {
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	delete(s.AccessTokens, signature)
	for requestID, tokenSignature := range s.AccessTokenRequestIDs {
		if tokenSignature == signature {
			delete(s.AccessTokenRequestIDs, requestID)
		}
	}
	return nil
}

func (s *MemoryStore) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	requestID := familyIDOf(req)

	s.tokenFamiliesMutex.RLock()
	defer s.tokenFamiliesMutex.RUnlock()

	if requestID != "" {
		if _, revoked := s.RevokedTokenFamilies[requestID]; revoked {
			return fosite.ErrInactiveToken
		}
		s.accessTokenRequestIDsMutex.RLock()
		accessMarker, accessExists := s.AccessTokenRequestIDs[requestID]
		s.accessTokenRequestIDsMutex.RUnlock()
		if accessExists && accessMarker == "" {
			return fosite.ErrInactiveToken
		}
		s.refreshTokenRequestIDsMutex.RLock()
		refreshMarker, refreshExists := s.RefreshTokenRequestIDs[requestID]
		s.refreshTokenRequestIDsMutex.RUnlock()
		if refreshExists && refreshMarker == "" {
			return fosite.ErrInactiveToken
		}
	}

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
	if marker, exists := s.RefreshTokenRequestIDs[requestID]; exists && marker == "" && requestID != "" {
		return fosite.ErrInactiveToken
	}

	s.tokenGenerationsMutex.Lock()
	if s.RefreshTokenGenerations == nil {
		s.RefreshTokenGenerations = make(map[string]uint64)
	}
	if s.RefreshTokenGenerationCounters == nil {
		s.RefreshTokenGenerationCounters = make(map[string]uint64)
	}
	if s.RefreshTokenRevocationGenerations == nil {
		s.RefreshTokenRevocationGenerations = make(map[string]uint64)
	}
	if s.RefreshTokenFamilies == nil {
		s.RefreshTokenFamilies = make(map[string]string)
	}
	if s.TokenFamilyClients == nil {
		s.TokenFamilyClients = make(map[string]string)
	}
	nextGeneration := s.RefreshTokenGenerationCounters[requestID] + 1
	if revoked := s.RefreshTokenRevocationGenerations[requestID]; revoked > 0 {
		s.tokenGenerationsMutex.Unlock()
		return fosite.ErrInactiveToken
	}
	s.RefreshTokenGenerations[signature] = nextGeneration
	s.RefreshTokenGenerationCounters[requestID] = nextGeneration
	s.RefreshTokenFamilies[signature] = requestID
	if req != nil && req.GetClient() != nil && req.GetClient().GetID() != "" {
		s.TokenFamilyClients[requestID] = req.GetClient().GetID()
	}
	s.tokenGenerationsMutex.Unlock()

	// Keep only one active generation per family. Older generations remain as
	// inactive tombstones so that re-use is detected as ErrInactiveToken
	// instead of being mistaken for a malformed token.
	for previousSignature, previous := range s.RefreshTokens {
		if previousSignature == signature || previous.Requester == nil {
			continue
		}
		if familyIDOf(previous.Requester) == requestID {
			previous.active = false
			previous.Active = false
			s.RefreshTokens[previousSignature] = previous
		}
	}

	s.RefreshTokens[signature] = StoreRefreshToken{active: true, Active: true, Requester: req, accessTokenSignature: accessTokenSignature}
	s.RefreshTokenRequestIDs[requestID] = signature
	return nil
}

func (s *MemoryStore) GetRefreshTokenSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	s.refreshTokensMutex.RLock()
	rel, ok := s.RefreshTokens[signature]
	s.refreshTokensMutex.RUnlock()
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if !rel.active && !rel.Active {
		return rel, fosite.ErrInactiveToken
	}

	if requestID := familyIDOf(rel.Requester); requestID != "" {
		s.tokenFamiliesMutex.RLock()
		_, revoked := s.RevokedTokenFamilies[requestID]
		s.tokenFamiliesMutex.RUnlock()
		s.tokenGenerationsMutex.RLock()
		revocationGeneration := s.RefreshTokenRevocationGenerations[requestID]
		generation := s.RefreshTokenGenerations[signature]
		s.tokenGenerationsMutex.RUnlock()
		if revoked || (revocationGeneration > 0 && generation <= revocationGeneration) {
			return rel, fosite.ErrInactiveToken
		}
		s.refreshTokenRequestIDsMutex.RLock()
		marker, markerExists := s.RefreshTokenRequestIDs[requestID]
		s.refreshTokenRequestIDsMutex.RUnlock()
		if markerExists && marker == "" {
			return rel, fosite.ErrInactiveToken
		}
		s.accessTokenRequestIDsMutex.RLock()
		accessMarker, accessMarkerExists := s.AccessTokenRequestIDs[requestID]
		s.accessTokenRequestIDsMutex.RUnlock()
		if accessMarkerExists && accessMarker == "" {
			return rel, fosite.ErrInactiveToken
		}
	}
	return rel, nil
}

func (s *MemoryStore) DeleteRefreshTokenSession(_ context.Context, signature string) error {
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	delete(s.RefreshTokens, signature)
	for requestID, tokenSignature := range s.RefreshTokenRequestIDs {
		if tokenSignature == signature {
			delete(s.RefreshTokenRequestIDs, requestID)
		}
	}
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
	revoked := make(map[string]time.Time)

	s.tokenFamiliesMutex.Lock()
	defer s.tokenFamiliesMutex.Unlock()

	// We first lock refreshTokenRequestIDsMutex and then refreshTokensMutex because this is the same order
	// locking happens in CreateRefreshTokenSession and using the same order prevents deadlocks.
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
	// Revoke every generation of the family, not only the request ID's most
	// recent mapping. The mapping may be missing after a restart or a failed
	// rotation, while an older session is still active.
	for signature, rel := range s.RefreshTokens {
		if rel.Requester == nil || familyIDOf(rel.Requester) != requestID {
			continue
		}
		if rel.active || rel.Active {
			rel.active = false
			rel.Active = false
			s.RefreshTokens[signature] = rel
		}
		if expiresAt := tokenExpiry(rel.Requester, fosite.RefreshToken); !expiresAt.IsZero() {
			revoked[signature] = expiresAt
		}
	}

	if requestID != "" {
		s.tokenGenerationsMutex.Lock()
		if s.RefreshTokenGenerationCounters == nil {
			s.RefreshTokenGenerationCounters = make(map[string]uint64)
		}
		if s.RefreshTokenRevocationGenerations == nil {
			s.RefreshTokenRevocationGenerations = make(map[string]uint64)
		}
		generation := s.RefreshTokenGenerationCounters[requestID]
		for signature := range revoked {
			if tokenGeneration := s.RefreshTokenGenerations[signature]; tokenGeneration > generation {
				generation = tokenGeneration
			}
		}
		if generation == 0 {
			generation = 1
		}
		if generation > s.RefreshTokenRevocationGenerations[requestID] {
			s.RefreshTokenRevocationGenerations[requestID] = generation
		}
		s.tokenGenerationsMutex.Unlock()
		s.setTokenFamilyRevokedLocked(requestID, fosite.RefreshToken, "", maxExpiry(revoked))
		s.RefreshTokenRequestIDs[requestID] = ""
	}

	s.recordRevokedSignatures(ctx, requestID, revoked)
	return nil
}

func (s *MemoryStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	revoked := make(map[string]time.Time)

	s.tokenFamiliesMutex.Lock()
	defer s.tokenFamiliesMutex.Unlock()

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
	for signature, rel := range s.AccessTokens {
		if rel == nil || familyIDOf(rel) != requestID {
			continue
		}
		if expiresAt := tokenExpiry(rel, fosite.AccessToken); !expiresAt.IsZero() {
			revoked[signature] = expiresAt
		}
		delete(s.AccessTokens, signature)
	}
	if requestID != "" {
		s.tokenGenerationsMutex.Lock()
		if s.AccessTokenGenerationCounters == nil {
			s.AccessTokenGenerationCounters = make(map[string]uint64)
		}
		if s.AccessTokenRevocationGenerations == nil {
			s.AccessTokenRevocationGenerations = make(map[string]uint64)
		}
		generation := s.AccessTokenGenerationCounters[requestID]
		for signature := range revoked {
			if tokenGeneration := s.AccessTokenGenerations[signature]; tokenGeneration > generation {
				generation = tokenGeneration
			}
		}
		if generation == 0 {
			generation = 1
		}
		if generation > s.AccessTokenRevocationGenerations[requestID] {
			s.AccessTokenRevocationGenerations[requestID] = generation
		}
		s.tokenGenerationsMutex.Unlock()
		s.setTokenFamilyRevokedLocked(requestID, fosite.AccessToken, "", maxExpiry(revoked))
		s.AccessTokenRequestIDs[requestID] = ""
	}

	s.recordRevokedSignatures(ctx, requestID, revoked)
	return nil
}

// RevokeTokenFamily atomically revokes both the access and refresh tokens of a
// request family and stores a durable tombstone. Because the tombstone is
// written under the same family lock as the cleanup, a caller can never
// observe a family in which only one half was revoked.
func (s *MemoryStore) RevokeTokenFamily(ctx context.Context, requestID string) error {
	revoked := make(map[string]time.Time)

	s.tokenFamiliesMutex.Lock()
	defer s.tokenFamiliesMutex.Unlock()

	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()
	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	if s.RefreshTokens == nil {
		s.RefreshTokens = make(map[string]StoreRefreshToken)
	}
	if s.AccessTokens == nil {
		s.AccessTokens = make(map[string]fosite.Requester)
	}
	if s.RefreshTokenRequestIDs == nil {
		s.RefreshTokenRequestIDs = make(map[string]string)
	}
	if s.AccessTokenRequestIDs == nil {
		s.AccessTokenRequestIDs = make(map[string]string)
	}
	for signature, rel := range s.RefreshTokens {
		if rel.Requester == nil || familyIDOf(rel.Requester) != requestID {
			continue
		}
		rel.active = false
		rel.Active = false
		s.RefreshTokens[signature] = rel
		if expiresAt := tokenExpiry(rel.Requester, fosite.RefreshToken); !expiresAt.IsZero() {
			revoked[signature] = expiresAt
		}
	}
	for signature, rel := range s.AccessTokens {
		if rel == nil || familyIDOf(rel) != requestID {
			continue
		}
		if expiresAt := tokenExpiry(rel, fosite.AccessToken); !expiresAt.IsZero() {
			revoked[signature] = expiresAt
		}
		delete(s.AccessTokens, signature)
	}
	if requestID != "" {
		s.tokenGenerationsMutex.Lock()
		if s.AccessTokenGenerationCounters == nil {
			s.AccessTokenGenerationCounters = make(map[string]uint64)
		}
		if s.AccessTokenRevocationGenerations == nil {
			s.AccessTokenRevocationGenerations = make(map[string]uint64)
		}
		if s.RefreshTokenGenerationCounters == nil {
			s.RefreshTokenGenerationCounters = make(map[string]uint64)
		}
		if s.RefreshTokenRevocationGenerations == nil {
			s.RefreshTokenRevocationGenerations = make(map[string]uint64)
		}
		accessGeneration := s.AccessTokenGenerationCounters[requestID]
		refreshGeneration := s.RefreshTokenGenerationCounters[requestID]
		for signature := range revoked {
			if tokenGeneration := s.AccessTokenGenerations[signature]; tokenGeneration > accessGeneration {
				accessGeneration = tokenGeneration
			}
			if tokenGeneration := s.RefreshTokenGenerations[signature]; tokenGeneration > refreshGeneration {
				refreshGeneration = tokenGeneration
			}
		}
		if accessGeneration == 0 {
			accessGeneration = 1
		}
		if refreshGeneration == 0 {
			refreshGeneration = 1
		}
		if accessGeneration > s.AccessTokenRevocationGenerations[requestID] {
			s.AccessTokenRevocationGenerations[requestID] = accessGeneration
		}
		if refreshGeneration > s.RefreshTokenRevocationGenerations[requestID] {
			s.RefreshTokenRevocationGenerations[requestID] = refreshGeneration
		}
		s.tokenGenerationsMutex.Unlock()
		s.setTokenFamilyRevokedLocked(requestID, "", "", maxExpiry(revoked))
		s.RefreshTokenRequestIDs[requestID] = ""
		s.AccessTokenRequestIDs[requestID] = ""
	}

	s.recordRevokedSignatures(ctx, requestID, revoked)
	return nil
}

func (s *MemoryStore) IsTokenFamilyRevoked(_ context.Context, requestID string) (bool, error) {
	if requestID == "" {
		return false, nil
	}
	s.tokenFamiliesMutex.RLock()
	defer s.tokenFamiliesMutex.RUnlock()
	if _, revoked := s.RevokedTokenFamilies[requestID]; revoked {
		return true, nil
	}
	s.tokenGenerationsMutex.RLock()
	accessRevoked := s.AccessTokenRevocationGenerations[requestID] > 0
	refreshRevoked := s.RefreshTokenRevocationGenerations[requestID] > 0
	s.tokenGenerationsMutex.RUnlock()
	if accessRevoked || refreshRevoked {
		return true, nil
	}

	// Token maps are also snapshotted by simple restart helpers that do not
	// know about newer fields. An empty request-ID marker written by a family
	// revocation carries the same fail-closed decision across such a restart.
	s.accessTokenRequestIDsMutex.RLock()
	accessMarker, accessExists := s.AccessTokenRequestIDs[requestID]
	s.accessTokenRequestIDsMutex.RUnlock()
	if accessExists && accessMarker == "" {
		return true, nil
	}
	s.refreshTokenRequestIDsMutex.RLock()
	refreshMarker, refreshExists := s.RefreshTokenRequestIDs[requestID]
	s.refreshTokenRequestIDsMutex.RUnlock()
	return refreshExists && refreshMarker == "", nil
}

func (s *MemoryStore) ResolveTokenFamily(_ context.Context, tokenType fosite.TokenType, signature string) (fosite.TokenFamilyResolution, error) {
	if signature == "" {
		return fosite.TokenFamilyResolution{}, fosite.ErrNotFound
	}

	s.tokenGenerationsMutex.RLock()
	defer s.tokenGenerationsMutex.RUnlock()

	var requestID string
	switch tokenType {
	case fosite.RefreshToken:
		requestID = s.RefreshTokenFamilies[signature]
	default:
		requestID = s.AccessTokenFamilies[signature]
	}
	if requestID == "" {
		return fosite.TokenFamilyResolution{}, fosite.ErrNotFound
	}
	return fosite.TokenFamilyResolution{
		RequestID: requestID,
		ClientID:  s.TokenFamilyClients[requestID],
	}, nil
}

func (s *MemoryStore) GetTokenFamilyRevocation(_ context.Context, requestID string) (fosite.TokenFamilyRevocationRecord, error) {
	s.tokenFamiliesMutex.RLock()
	defer s.tokenFamiliesMutex.RUnlock()
	record, ok := s.RevokedTokenFamilies[requestID]
	if !ok {
		return fosite.TokenFamilyRevocationRecord{}, fosite.ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) RecordTokenFamilyRevocation(_ context.Context, record fosite.TokenFamilyRevocationRecord) error {
	if record.RequestID == "" {
		return nil
	}

	s.tokenFamiliesMutex.Lock()
	defer s.tokenFamiliesMutex.Unlock()

	if s.RevokedTokenFamilies == nil {
		s.RevokedTokenFamilies = make(map[string]fosite.TokenFamilyRevocationRecord)
	}
	existing, ok := s.RevokedTokenFamilies[record.RequestID]
	if !ok {
		s.TokenFamilyRevocationCounter++
		record.Generation = s.TokenFamilyRevocationCounter
		if record.RevokedAt.IsZero() {
			record.RevokedAt = time.Now().UTC()
		}
		s.RevokedTokenFamilies[record.RequestID] = record
		return nil
	}

	if existing.Source == "" {
		if record.TokenType != "" {
			existing.TokenType = record.TokenType
			existing.TokenUse = record.TokenUse
		}
		if record.TokenSignature != "" {
			existing.TokenSignature = record.TokenSignature
		}
		if record.ClientID != "" {
			existing.ClientID = record.ClientID
		}
		if record.Stage != "" {
			existing.Stage = record.Stage
		}
		existing.Source = record.Source
	}
	if existing.ExpiresAt.IsZero() || (!record.ExpiresAt.IsZero() && record.ExpiresAt.After(existing.ExpiresAt)) {
		existing.ExpiresAt = record.ExpiresAt
	}
	s.RevokedTokenFamilies[record.RequestID] = existing
	return nil
}

// RecordTokenRevocation stores durable revocation evidence for a token digest.
// Recording the same digest again is idempotent: it preserves the original
// revocation generation and timestamp so that retries cannot move a revoked
// token back into an active state.
func (s *MemoryStore) RecordTokenRevocation(_ context.Context, record fosite.TokenRevocationRecord) error {
	if record.TokenDigest == "" {
		return nil
	}

	s.tokenRevocationsMutex.Lock()
	defer s.tokenRevocationsMutex.Unlock()

	if s.TokenRevocations == nil {
		s.TokenRevocations = make(map[string]fosite.TokenRevocationRecord)
	}

	existing, ok := s.TokenRevocations[record.TokenDigest]
	if !ok {
		s.TokenRevocationGeneration++
		record.Generation = s.TokenRevocationGeneration
		if record.RevokedAt.IsZero() {
			record.RevokedAt = time.Now().UTC()
		}
		if record.RequestID == "" {
			record.RequestID = record.RequestFamily
		}
		if record.RequestFamily == "" {
			record.RequestFamily = record.RequestID
		}
		if record.TokenType == "" {
			record.TokenType = record.TokenUse
		}
		if record.TokenUse == "" {
			record.TokenUse = record.TokenType
		}
		s.TokenRevocations[record.TokenDigest] = record
		return nil
	}

	if existing.TokenSignature == "" {
		existing.TokenSignature = record.TokenSignature
	}
	if existing.ClientID == "" {
		existing.ClientID = record.ClientID
	}
	if existing.TokenUse == "" {
		existing.TokenUse = record.TokenUse
	}
	if existing.TokenType == "" {
		existing.TokenType = record.TokenType
	}
	if existing.RequestID == "" {
		existing.RequestID = record.RequestID
	}
	if existing.RequestFamily == "" {
		existing.RequestFamily = record.RequestFamily
	}
	if existing.Source == "" {
		existing.Source = record.Source
	}
	if existing.Stage == "" {
		existing.Stage = record.Stage
	}
	if existing.ExpiresAt.IsZero() || (!record.ExpiresAt.IsZero() && record.ExpiresAt.After(existing.ExpiresAt)) {
		existing.ExpiresAt = record.ExpiresAt
	}
	if record.RevocationGeneration > existing.RevocationGeneration {
		existing.RevocationGeneration = record.RevocationGeneration
	}
	s.TokenRevocations[record.TokenDigest] = existing
	return nil
}

func (s *MemoryStore) GetTokenRevocationState(_ context.Context, tokenDigest string) (fosite.TokenRevocationRecord, error) {
	s.tokenRevocationsMutex.RLock()
	defer s.tokenRevocationsMutex.RUnlock()
	record, ok := s.TokenRevocations[tokenDigest]
	if !ok {
		return fosite.TokenRevocationRecord{}, fosite.ErrNotFound
	}
	return record, nil
}

func (s *MemoryStore) IsTokenRevoked(_ context.Context, tokenDigest string) (bool, error) {
	if tokenDigest == "" {
		return false, nil
	}

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

func (s *MemoryStore) IsTokenSignatureRevoked(_ context.Context, signature string) (bool, error) {
	if signature == "" {
		return false, nil
	}

	s.revokedSignaturesMutex.RLock()
	expiresAt, ok := s.RevokedTokenSignatures[signature]
	s.revokedSignaturesMutex.RUnlock()
	if !ok {
		return false, nil
	}
	if !expiresAt.IsZero() && !time.Now().UTC().Before(expiresAt) {
		s.revokedSignaturesMutex.Lock()
		delete(s.RevokedTokenSignatures, signature)
		delete(s.TokenFamilyBySignature, signature)
		s.revokedSignaturesMutex.Unlock()
		return false, nil
	}
	return true, nil
}

// GetTokenFamilyBySignature returns the request family associated with a
// revoked token signature. It is used for audit reports when the token session
// itself is no longer available.
func (s *MemoryStore) GetTokenFamilyBySignature(_ context.Context, signature string) (string, error) {
	s.revokedSignaturesMutex.RLock()
	defer s.revokedSignaturesMutex.RUnlock()
	requestID, ok := s.TokenFamilyBySignature[signature]
	if !ok {
		return "", fosite.ErrNotFound
	}
	return requestID, nil
}

func (s *MemoryStore) setTokenFamilyRevokedLocked(requestID string, tokenType fosite.TokenType, signature string, expiresAt time.Time) {
	if requestID == "" {
		return
	}
	if s.RevokedTokenFamilies == nil {
		s.RevokedTokenFamilies = make(map[string]fosite.TokenFamilyRevocationRecord)
	}

	record, exists := s.RevokedTokenFamilies[requestID]
	if !exists {
		s.TokenFamilyRevocationCounter++
		record = fosite.TokenFamilyRevocationRecord{
			RequestID:  requestID,
			RevokedAt:  time.Now().UTC(),
			Generation: s.TokenFamilyRevocationCounter,
			Stage:      fosite.TokenStatusStageRevoked,
		}
	}
	if record.TokenType == "" && tokenType != "" {
		record.TokenType = tokenType
		record.TokenUse = tokenType
	}
	if record.TokenSignature == "" && signature != "" {
		record.TokenSignature = signature
	}
	if record.ExpiresAt.IsZero() || (!expiresAt.IsZero() && expiresAt.After(record.ExpiresAt)) {
		record.ExpiresAt = expiresAt
	}
	if record.Stage == "" {
		record.Stage = fosite.TokenStatusStageRevoked
	}
	s.RevokedTokenFamilies[requestID] = record
}

func (s *MemoryStore) recordRevokedSignatures(_ context.Context, requestID string, signatures map[string]time.Time) {
	if len(signatures) == 0 {
		return
	}

	s.revokedSignaturesMutex.Lock()
	defer s.revokedSignaturesMutex.Unlock()
	if s.RevokedTokenSignatures == nil {
		s.RevokedTokenSignatures = make(map[string]time.Time)
	}
	if s.TokenFamilyBySignature == nil {
		s.TokenFamilyBySignature = make(map[string]string)
	}
	for signature, expiresAt := range signatures {
		if existing, ok := s.RevokedTokenSignatures[signature]; !ok || existing.IsZero() || expiresAt.IsZero() || expiresAt.After(existing) {
			s.RevokedTokenSignatures[signature] = expiresAt
		}
		if requestID != "" {
			s.TokenFamilyBySignature[signature] = requestID
		}
	}
}

func familyIDOf(request fosite.Requester) string {
	if request == nil {
		return ""
	}
	return request.GetID()
}

func tokenExpiry(request fosite.Requester, tokenType fosite.TokenType) time.Time {
	if request == nil || request.GetSession() == nil {
		return time.Time{}
	}
	return request.GetSession().GetExpiresAt(tokenType)
}

func maxExpiry(expiries map[string]time.Time) time.Time {
	var max time.Time
	for _, expiresAt := range expiries {
		if expiresAt.After(max) {
			max = expiresAt
		}
	}
	return max
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
	s.tokenFamiliesMutex.RLock()
	defer s.tokenFamiliesMutex.RUnlock()

	if requestID != "" {
		if _, revoked := s.RevokedTokenFamilies[requestID]; revoked {
			return fosite.ErrInactiveToken
		}
		s.tokenGenerationsMutex.RLock()
		accessRevoked := s.AccessTokenRevocationGenerations[requestID] > 0
		refreshRevoked := s.RefreshTokenRevocationGenerations[requestID] > 0
		s.tokenGenerationsMutex.RUnlock()
		if accessRevoked || refreshRevoked {
			return fosite.ErrInactiveToken
		}
		s.accessTokenRequestIDsMutex.RLock()
		accessMarker, accessExists := s.AccessTokenRequestIDs[requestID]
		s.accessTokenRequestIDsMutex.RUnlock()
		s.refreshTokenRequestIDsMutex.RLock()
		refreshMarker, refreshExists := s.RefreshTokenRequestIDs[requestID]
		s.refreshTokenRequestIDsMutex.RUnlock()
		if (accessExists && accessMarker == "") || (refreshExists && refreshMarker == "") {
			return fosite.ErrInactiveToken
		}
	}

	// Lock the refresh token first and the access token second. This is the
	// same order used by family revocation and avoids deadlocks.
	s.refreshTokenRequestIDsMutex.Lock()
	defer s.refreshTokenRequestIDsMutex.Unlock()
	s.refreshTokensMutex.Lock()
	defer s.refreshTokensMutex.Unlock()

	if s.RefreshTokens == nil {
		s.RefreshTokens = make(map[string]StoreRefreshToken)
	}

	rel, ok := s.RefreshTokens[refreshTokenSignature]
	if !ok {
		return fosite.ErrNotFound
	}
	if rel.Requester == nil || familyIDOf(rel.Requester) != requestID {
		return fosite.ErrNotFound
	}
	if !rel.active && !rel.Active {
		return fosite.ErrInactiveToken
	}

	rel.active = false
	rel.Active = false
	s.RefreshTokens[refreshTokenSignature] = rel

	s.accessTokenRequestIDsMutex.Lock()
	defer s.accessTokenRequestIDsMutex.Unlock()
	s.accessTokensMutex.Lock()
	defer s.accessTokensMutex.Unlock()

	// Only invalidate the access token that belongs to the presented
	// generation. A concurrent request may already have created a newer
	// generation, which must not be touched by this rotation.
	if rel.accessTokenSignature != "" {
		delete(s.AccessTokens, rel.accessTokenSignature)
		if s.AccessTokenRequestIDs[requestID] == rel.accessTokenSignature {
			delete(s.AccessTokenRequestIDs, requestID)
		}
		_ = s.RecordTokenSignatureRevocation(ctx, rel.accessTokenSignature, tokenExpiry(rel.Requester, fosite.AccessToken))
	}

	return nil
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
