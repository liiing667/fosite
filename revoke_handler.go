// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/ory/x/errorsx"
	"github.com/ory/x/otelx"
	"go.opentelemetry.io/otel/trace"

	"github.com/pkg/errors"
)

// NewRevocationRequest handles incoming token revocation requests and
// validates various parameters as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
//
// The authorization server first validates the client credentials (in
// case of a confidential client) and then verifies whether the token
// was issued to the client making the revocation request.  If this
// validation fails, the request is refused and the client is informed
// of the error by the authorization server as described below.
//
// In the next step, the authorization server invalidates the token.
// The invalidation takes place immediately, and the token cannot be
// used again after the revocation.
//
// * https://tools.ietf.org/html/rfc7009#section-2.2
// An invalid token type hint value is ignored by the authorization
// server and does not influence the revocation response.
func (f *Fosite) NewRevocationRequest(ctx context.Context, r *http.Request) error {
	_, err := f.NewRevocationRequestWithReport(ctx, r)
	return err
}

// NewRevocationRequestWithReport behaves like NewRevocationRequest but also
// returns a TokenStatusReport with the token digest, authenticated client,
// revocation source, revocation generation and the precise stage that failed.
// The report does not alter any OAuth error code or HTTP response.
func (f *Fosite) NewRevocationRequestWithReport(ctx context.Context, r *http.Request) (report TokenStatusReport, err error) {
	ctx, span := trace.SpanFromContext(ctx).TracerProvider().Tracer("github.com/ory/fosite").Start(ctx, "Fosite.NewRevocationRequest")
	defer otelx.End(span, &err)

	defer func() {
		if report.TokenDigest == "" {
			if token := r.PostForm.Get("token"); token != "" {
				report.TokenDigest = TokenDigest(token)
			}
		}
		if err != nil {
			report.Active = false
			report.Revoked = false
			if report.Stage == "" {
				report.Stage = TokenStatusStageRevocation
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
	}()

	ctx = context.WithValue(ctx, RequestContextKey, r)

	if r.Method != "POST" {
		return report, errorsx.WithStack(ErrInvalidRequest.WithHintf("HTTP method is '%s' but expected 'POST'.", r.Method))
	} else if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
		return report, errorsx.WithStack(ErrInvalidRequest.WithHint("Unable to parse HTTP body, make sure to send a properly formatted form request body.").WithWrap(err).WithDebug(err.Error()))
	} else if len(r.PostForm) == 0 {
		return report, errorsx.WithStack(ErrInvalidRequest.WithHint("The POST body can not be empty."))
	}

	if id, _, ok := r.BasicAuth(); ok {
		report.ClientID = id
		if decoded, decodeErr := url.QueryUnescape(id); decodeErr == nil {
			report.ClientID = decoded
		}
	} else if clientID := r.PostForm.Get("client_id"); clientID != "" {
		report.ClientID = clientID
	}

	client, err := f.AuthenticateClient(ctx, r, r.PostForm)
	if err != nil {
		report.Stage = TokenStatusStageAuthentication
		return report, err
	}
	report.ClientID = client.GetID()

	token := r.PostForm.Get("token")
	tokenTypeHint := TokenType(r.PostForm.Get("token_type_hint"))
	report.TokenUse = TokenUse(tokenTypeHint)

	var found = false
	var source string
	for _, loader := range f.Config.GetRevocationHandlers(ctx) {
		if err := loader.RevokeToken(ctx, token, tokenTypeHint, client); err == nil {
			found = true
			if source == "" {
				source = fmt.Sprintf("%T", loader)
			}
		} else if errors.Is(err, ErrUnknownRequest) {
			// do nothing
		} else if err != nil {
			report.Source = fmt.Sprintf("%T", loader)
			report.Stage = TokenStatusStageRevocation
			return report, err
		}
	}

	if !found {
		report.Stage = TokenStatusStageNotFound
		return report, errorsx.WithStack(ErrInvalidRequest)
	}

	report.TokenDigest = TokenDigest(token)
	report.Source = source
	report.Active = false
	report.Revoked = true
	report.Stage = TokenStatusStageRevoked
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

	return report, nil
}

// WriteRevocationResponse writes a token revocation response as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.2
//
// The authorization server responds with HTTP status code 200 if the
// token has been revoked successfully or if the client submitted an
// invalid token.
//
// Note: invalid tokens do not cause an error response since the client
// cannot handle such an error in a reasonable way.  Moreover, the
// purpose of the revocation request, invalidating the particular token,
// is already achieved.
func (f *Fosite) WriteRevocationResponse(ctx context.Context, rw http.ResponseWriter, err error) {
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")

	if err == nil {
		rw.WriteHeader(http.StatusOK)
		return
	}

	if errors.Is(err, ErrInvalidRequest) {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

		js, err := json.Marshal(ErrInvalidRequest)
		if err != nil {
			http.Error(rw, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(ErrInvalidRequest.CodeField)
		_, _ = rw.Write(js)
	} else if errors.Is(err, ErrInvalidClient) {
		rw.Header().Set("Content-Type", "application/json;charset=UTF-8")

		js, err := json.Marshal(ErrInvalidClient)
		if err != nil {
			http.Error(rw, fmt.Sprintf(`{"error": "%s"}`, err.Error()), http.StatusInternalServerError)
			return
		}

		rw.WriteHeader(ErrInvalidClient.CodeField)
		_, _ = rw.Write(js)
	} else {
		// 200 OK
		rw.WriteHeader(http.StatusOK)
	}
}
