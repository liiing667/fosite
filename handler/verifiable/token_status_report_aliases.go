// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package verifiable

import "github.com/ory/fosite"

// IntrospectionReport and RevocationReport are the shared audit evidence
// types used by token introspection and revocation. They are aliases so that
// verifiable-credential consumers can inspect token digests, clients, status
// sources and revocation generations without depending on implementation
// details of the storage layer.
type IntrospectionReport = fosite.TokenStatusReport

// RevocationReport is the evidence returned after revoking a token.
type RevocationReport = fosite.TokenStatusReport

// TokenStatusReport is an alias for IntrospectionReport and RevocationReport.
type TokenStatusReport = fosite.TokenStatusReport
