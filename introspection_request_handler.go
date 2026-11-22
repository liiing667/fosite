// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"go.opentelemetry.io/otel/trace"
	"golang.org/x/text/language"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
)

// NewIntrospectionRequest initiates token introspection as defined in
// https://tools.ietf.org/html/rfc7662#section-2.1
//
// The protected resource calls the introspection endpoint using an HTTP
// POST [RFC7231] request with parameters sent as
// "application/x-www-form-urlencoded" data as defined in
// [W3C.REC-html5-20141028].  The protected resource sends a parameter
// representing the token along with optional parameters representing
// additional context that is known by the protected resource to aid the
// authorization server in its response.
//
// * token
// REQUIRED.  The string value of the token.  For access tokens, this
// is the "access_token" value returned from the token endpoint
// defined in OAuth 2.0 [RFC6749], Section 5.1.  For refresh tokens,
// this is the "refresh_token" value returned from the token endpoint
// as defined in OAuth 2.0 [RFC6749], Section 5.1.  Other token types
// are outside the scope of this specification.
//
// * token_type_hint
// OPTIONAL.  A hint about the type of the token submitted for
// introspection.  The protected resource MAY pass this parameter to
// help the authorization server optimize the token lookup.  If the
// server is unable to locate the token using the given hint, it MUST
// extend its search across all of its supported token types.  An
// authorization server MAY ignore this parameter, particularly if it
// is able to detect the token type automatically.  Values for this
// field are defined in the "OAuth Token Type Hints" registry defined
// in OAuth Token Revocation [RFC7009].
//
// The introspection endpoint MAY accept other OPTIONAL parameters to
// provide further context to the query.  For instance, an authorization
// server may desire to know the IP address of the client accessing the
// protected resource to determine if the correct client is likely to be
// presenting the token.  The definition of this or any other parameters
// are outside the scope of this specification, to be defined by service
// documentation or extensions to this specification.  If the
// authorization server is unable to determine the state of the token
// without additional information, it SHOULD return an introspection
// response indicating the token is not active as described in
// Section 2.2.
//
// To prevent token scanning attacks, the endpoint MUST also require
// some form of authorization to access this endpoint, such as client
// authentication as described in OAuth 2.0 [RFC6749] or a separate
// OAuth 2.0 access token such as the bearer token described in OAuth
// 2.0 Bearer Token Usage [RFC6750].  The methods of managing and
// validating these authentication credentials are out of scope of this
// specification.
//
// For example, the following shows a protected resource calling the
// token introspection endpoint to query about an OAuth 2.0 bearer
// token.  The protected resource is using a separate OAuth 2.0 bearer
// token to authorize this call.
//
// The following is a non-normative example request:
//
//	POST /introspect HTTP/1.1
//	Host: server.example.com
//	Accept: application/json
//	Content-Type: application/x-www-form-urlencoded
//	Authorization: Bearer 23410913-abewfq.123483
//
//	token=2YotnFZFEjr1zCsicMWpAA
//
// In this example, the protected resource uses a client identifier and
// client secret to authenticate itself to the introspection endpoint.
// The protected resource also sends a token type hint indicating that
// it is inquiring about an access token.
//
// The following is a non-normative example request:
//
//	POST /introspect HTTP/1.1
//	Host: server.example.com
//	Accept: application/json
//	Content-Type: application/x-www-form-urlencoded
//	Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
//
//	token=mF_9.B5f-4.1JqM&token_type_hint=access_token
func (f *Fosite) NewIntrospectionRequest(ctx context.Context, r *http.Request, session Session) (IntrospectionResponder, error) {
	responder, report, err := f.NewIntrospectionRequestWithReport(ctx, r, session)
	if response, ok := responder.(*IntrospectionResponse); ok && response != nil {
		response.Report = report
	}
	return responder, err
}

// NewIntrospectionRequestWithReport behaves like NewIntrospectionRequest but
// additionally returns a TokenStatusReport containing the token digest,
// client, status source and revocation generation. The report is suitable for
// audit logs and tests; it is never included in the introspection response.
func (f *Fosite) NewIntrospectionRequestWithReport(ctx context.Context, r *http.Request, session Session) (responder IntrospectionResponder, report TokenStatusReport, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewIntrospectionRequest")
	defer otelx.End(span, &err)

	defer func() {
		if report.TokenDigest == "" {
			if token := r.PostForm.Get("token"); token != "" {
				report.TokenDigest = TokenDigest(token)
			}
		}
		if err != nil {
			report.Active = false
			if report.Stage == "" {
				report.Stage = TokenStatusStageIntrospection
			}
			if report.Error == "" {
				report.Error = err.Error()
			}
		}
		if report.Source == "" {
			report.Source = report.Stage
		}
		if report.StatusSource == "" {
			report.StatusSource = report.Source
		}
		if report.Stage != "" && report.Stage != TokenStatusStageRevoked && report.Stage != TokenStatusStageActive {
			report.FailureLocation = report.Stage
		}
		if response, ok := responder.(*IntrospectionResponse); ok && response != nil {
			response.Report = report
		}
	}()

	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != "POST" {
		return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	} else if len(r.PostForm) == 0 {
		return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	token := r.PostForm.Get("token")
	tokenTypeHint := r.PostForm.Get("token_type_hint")
	scope := r.PostForm.Get("scope")
	if clientToken := AccessTokenFromRequest(r); clientToken != "" {
		if token == clientToken {
			report.Stage = TokenStatusStageAuthentication
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("Bearer and introspection token are identical."))
		}

		if tu, _, err := f.IntrospectToken(ctx, clientToken, AccessToken, session.Clone()); err != nil {
			report.Stage = TokenStatusStageAuthentication
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("HTTP Authorization header missing, malformed, or credentials used are invalid."))
		} else if tu != "" && tu != AccessToken {
			report.Stage = TokenStatusStageAuthentication
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHintf("HTTP Authorization header did not provide a token of type 'access_token', got type '%s'.", tu))
		}
	} else {
		id, secret, ok := r.BasicAuth()
		if !ok {
			report.Stage = TokenStatusStageAuthentication
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("HTTP Authorization header missing."))
		}

		clientID, err := url.QueryUnescape(id)
		if err != nil {
			report.Stage = TokenStatusStageAuthentication
			report.ClientID = id
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("Unable to decode OAuth 2.0 Client ID from HTTP basic authorization header, make sure it is properly encoded.").WithWrap(err).WithDebug(err.Error()))
		}

		clientSecret, err := url.QueryUnescape(secret)
		if err != nil {
			report.Stage = TokenStatusStageAuthentication
			report.ClientID = clientID
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("Unable to decode OAuth 2.0 Client Secret from HTTP basic authorization header, make sure it is properly encoded.").WithWrap(err).WithDebug(err.Error()))
		}

		client, err := f.Store.GetClient(ctx, clientID)
		if err != nil {
			report.Stage = TokenStatusStageAuthentication
			report.ClientID = clientID
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("Unable to find OAuth 2.0 Client from HTTP basic authorization header.").WithWrap(err).WithDebug(err.Error()))
		}

		// Enforce client authentication
		if err := f.checkClientSecret(ctx, client, []byte(clientSecret)); err != nil {
			report.Stage = TokenStatusStageAuthentication
			report.ClientID = clientID
			return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrRequestUnauthorized.WithHint("OAuth 2.0 Client credentials are invalid."))
		}
		report.ClientID = clientID
	}

	tu, ar, source, err := f.introspectToken(ctx, token, TokenUse(tokenTypeHint), session, RemoveEmpty(strings.Split(scope, " "))...)
	if err != nil {
		report.TokenDigest = TokenDigest(token)
		report.Source = source
		report.Active = false
		if provider, ok := f.Store.(TokenRevocationStateProvider); ok {
			if record, recordErr := provider.GetTokenRevocationState(ctx, report.TokenDigest); recordErr == nil {
				report.Generation = record.Generation
				report.RevocationGeneration = record.RevocationGeneration
				report.RevokedAt = record.RevokedAt
				report.TokenSignature = record.TokenSignature
				report.Revoked = true
				if record.Source != "" {
					report.StatusSource = record.Source
				}
				if record.TokenUse != "" {
					report.TokenUse = record.TokenUse
				}
			}
		}
		return &IntrospectionResponse{Active: false}, report, errorsx.WithStack(ErrInactiveToken.WithHint("An introspection strategy indicated that the token is inactive.").WithWrap(err).WithDebug(err.Error()))
	}
	accessTokenType := ""

	if tu == AccessToken {
		accessTokenType = BearerAccessToken
	}

	report.TokenDigest = TokenDigest(token)
	report.TokenUse = tu
	report.Active = true
	report.Source = source
	report.Stage = TokenStatusStageActive
	if ar != nil && ar.GetClient() != nil && ar.GetClient().GetID() != "" {
		report.ClientID = ar.GetClient().GetID()
	}
	if provider, ok := f.Store.(TokenRevocationStateProvider); ok {
		if record, recordErr := provider.GetTokenRevocationState(ctx, report.TokenDigest); recordErr == nil {
			report.Generation = record.Generation
			report.RevocationGeneration = record.RevocationGeneration
			report.RevokedAt = record.RevokedAt
			report.TokenSignature = record.TokenSignature
			if record.Source != "" {
				report.StatusSource = record.Source
			}
			if record.TokenUse != "" {
				report.TokenUse = record.TokenUse
			}
		}
	}
	if report.StatusSource == "" {
		report.StatusSource = report.Source
	}
	if report.Stage != TokenStatusStageRevoked && report.Stage != TokenStatusStageActive {
		report.FailureLocation = report.Stage
	}

	return &IntrospectionResponse{
		Active:          true,
		AccessRequester: ar,
		TokenUse:        tu,
		AccessTokenType: accessTokenType,
		Report:          report,
	}, report, nil
}

type IntrospectionResponse struct {
	Active          bool              `json:"active"`
	AccessRequester AccessRequester   `json:"extra"`
	TokenUse        TokenUse          `json:"token_use,omitempty"`
	AccessTokenType string            `json:"token_type,omitempty"`
	Lang            language.Tag      `json:"-"`
	Report          TokenStatusReport `json:"-"`
}

func (r *IntrospectionResponse) IsActive() bool {
	return r.Active
}

func (r *IntrospectionResponse) GetAccessRequester() AccessRequester {
	return r.AccessRequester
}

func (r *IntrospectionResponse) GetTokenUse() TokenUse {
	return r.TokenUse
}

func (r *IntrospectionResponse) GetAccessTokenType() string {
	return r.AccessTokenType
}

// GetReport returns the audit evidence collected for this introspection
// request. It contains the token digest, client, status source and revocation
// generation, and is never serialized into the RFC 7662 response.
func (r *IntrospectionResponse) GetReport() TokenStatusReport {
	return r.Report
}
