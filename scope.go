package dcql

import (
	"fmt"
	"slices"
)

// RegisteredCredential mirrors one Credential entry of the client's ARF TS5
// registered intended use — the Claim ([ARF TS5 v1.3 §2.4.1]) and Credential
// ([ARF TS5 v1.3 §2.4.4]) classes.
type RegisteredCredential struct {
	Format         string
	DoctypesOrVCTs []string    // registered doctype(s) (mdoc) or vct value(s) (sd-jwt)
	AllClaims      bool        // registration covers every claim of the credential
	Claims         []ClaimPath // registered claim paths when AllClaims is false
}

// WithinScope checks that every claim the query COULD request (union over
// claims, regardless of claim_sets choice) lies within the registered
// intended use. Drives err:client:scope-exceeded at the management boundary.
// Offense strings carry positions and paths — never claim values.
// The query must have passed Validate(); on unvalidated queries the check
// fails closed per-credential but individual guarantees are weaker.
// A claim is in scope when ANY covering registration lists it (union across
// registrations).
func (q *Query) WithinScope(registered []RegisteredCredential) (bool, []string) {
	var offenses []string
	for i := range q.Credentials {
		cq := &q.Credentials[i]
		regs := coveringRegistrations(cq, registered)
		if len(regs) == 0 {
			offenses = append(offenses, fmt.Sprintf("credentials[%d](%s): format/doctype/vct not registered", i, cq.ID))
			continue
		}
		if len(cq.Claims) == 0 {
			// [OID4VP §6.4.1]: claims absent still discloses the credential's
			// mandatory-to-present claims — requires a full registration.
			if !anyAllClaims(regs) {
				offenses = append(offenses, fmt.Sprintf("credentials[%d](%s): requests mandatory claim set but registration lists specific claims only", i, cq.ID))
			}
			continue
		}
		for j := range cq.Claims {
			if !pathRegistered(cq.Claims[j].Path, regs) {
				offenses = append(offenses, fmt.Sprintf("credentials[%d](%s): %s", i, cq.ID, cq.Claims[j].Path.String()))
			}
		}
	}
	return len(offenses) == 0, offenses
}

func coveringRegistrations(cq *CredentialQuery, registered []RegisteredCredential) []*RegisteredCredential {
	var out []*RegisteredCredential
	if cq.Meta == nil {
		return nil
	}
	for i := range registered {
		r := &registered[i]
		if r.Format != cq.Format {
			continue
		}
		switch cq.Format {
		case FormatMdoc:
			if slices.Contains(r.DoctypesOrVCTs, cq.Meta.DoctypeValue) {
				out = append(out, r)
			}
		case FormatSDJWT:
			if len(cq.Meta.VCTValues) == 0 {
				continue
			}
			// every vct the query would accept must be registered
			all := true
			for _, vct := range cq.Meta.VCTValues {
				if !slices.Contains(r.DoctypesOrVCTs, vct) {
					all = false
					break
				}
			}
			if all {
				out = append(out, r)
			}
		}
	}
	return out
}

func anyAllClaims(regs []*RegisteredCredential) bool {
	for _, r := range regs {
		if r.AllClaims {
			return true
		}
	}
	return false
}

func pathRegistered(p ClaimPath, regs []*RegisteredCredential) bool {
	for _, r := range regs {
		if r.AllClaims {
			return true
		}
		for _, rp := range r.Claims {
			if pathCovered(rp, p) {
				return true
			}
		}
	}
	return false
}

// pathCovered: a registered path covers a query path of equal length when
// each element matches; a registered wildcard also covers a concrete index
// or wildcard at that position (recorded interpretation).
func pathCovered(registered, query ClaimPath) bool {
	if len(registered) != len(query) {
		return false
	}
	for i := range registered {
		r, qe := registered[i], query[i]
		switch r.Kind {
		case KindKey:
			if qe.Kind != KindKey || qe.Key != r.Key {
				return false
			}
		case KindWildcard:
			if qe.Kind != KindWildcard && qe.Kind != KindIndex {
				return false
			}
		case KindIndex:
			if qe.Kind != KindIndex || qe.Index != r.Index {
				return false
			}
		default:
			return false
		}
	}
	return true
}
