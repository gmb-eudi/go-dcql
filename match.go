package dcql

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
)

// Candidate is one already-verified credential presented for a credential
// query (pipeline steps 3–6 done). WP-05 decision: the matcher operates
// post-verification only — no crypto here; the pipeline enforces that no
// unverified candidate enters.
type Candidate struct {
	QueryCredID     string         // vp_token key: which credential query it answers (OID4VP §8.1)
	Format          string         // mso_mdoc | dc+sd-jwt
	DoctypeOrVCT    string         // mdoc doctype or SD-JWT VC vct
	Claims          map[string]any // mdoc: namespace → element → value; sd-jwt: claims object
	HolderBound     bool           // cryptographic holder binding verified (pipeline step 6)
	IssuerAuthority AuthorityRef
}

// AuthorityRef carries trust references of the candidate's verified issuer
// chain, supplied by the pipeline; compared against trusted_authorities
// queries (OID4VP §6.1.1, matching logic in T-05.5).
type AuthorityRef struct {
	AKIs            []string // base64url KeyIdentifier values of chain certs (aki)
	TrustedListURIs []string // ETSI TS 119 612 trusted list(s) of the anchor (etsi_tl)
	FederationIDs   []string // OpenID Federation Entity Identifiers (openid_federation)
}

// UnmetReason categorizes why a credential query or credential set could
// not be satisfied.
type UnmetReason string

// Reasons a credential query or credential set can go unmet.
const (
	UnmetNoCandidate   UnmetReason = "no-candidate"
	UnmetFormat        UnmetReason = "format-mismatch"
	UnmetMeta          UnmetReason = "meta-mismatch"
	UnmetClaims        UnmetReason = "claims-unsatisfied"
	UnmetHolderBinding UnmetReason = "holder-binding-missing"
	UnmetAuthority     UnmetReason = "authority-mismatch"
	UnmetMultiple      UnmetReason = "multiple-not-allowed"
	UnmetSet           UnmetReason = "credential-set-unsatisfied"
	UnmetUnknownQuery  UnmetReason = "unknown-credential-query"
)

// Unmet explains one failed query or set. Paths only — never claim values
// (hard rule 3; safe for the verification report).
type Unmet struct {
	CredentialID string // credential query id; "" for set-level entries
	SetIndex     int    // index into credential_sets; -1 otherwise
	Reason       UnmetReason
	Paths        []string
}

// MatchResult reports the outcome. Unmet may be non-empty even when
// Satisfied is true: it also lists optional queries/sets that did not match.
type MatchResult struct {
	Satisfied    bool
	ByCredential map[string][]string // credential query id → claim paths actually used
	Unmet        []Unmet
}

// Match decides whether the verified candidates satisfy the query
// (OID4VP §6.4). Precondition: q passed Validate(). Fail closed: a candidate
// answering an unknown credential query id (over-disclosure, pipeline step
// 8) makes the whole result unsatisfied.
func (q *Query) Match(cands []Candidate) MatchResult {
	res := MatchResult{ByCredential: map[string][]string{}}
	known := map[string]bool{}
	for i := range q.Credentials {
		known[q.Credentials[i].ID] = true
	}
	overDisclosed := false
	byID := map[string][]Candidate{}
	for _, cand := range cands {
		if !known[cand.QueryCredID] {
			overDisclosed = true
			res.Unmet = append(res.Unmet, Unmet{CredentialID: cand.QueryCredID, SetIndex: -1, Reason: UnmetUnknownQuery})
			continue
		}
		byID[cand.QueryCredID] = append(byID[cand.QueryCredID], cand)
	}
	satisfied := map[string]bool{}
	for i := range q.Credentials {
		cq := &q.Credentials[i]
		ok, paths, unmet := matchCredential(cq, byID[cq.ID])
		if ok {
			satisfied[cq.ID] = true
			res.ByCredential[cq.ID] = paths
		} else {
			res.Unmet = append(res.Unmet, unmet...)
		}
	}
	res.Satisfied = q.setsSatisfied(satisfied, &res) && !overDisclosed
	return res
}

func matchCredential(cq *CredentialQuery, cands []Candidate) (bool, []string, []Unmet) {
	if len(cands) == 0 {
		return false, nil, []Unmet{{CredentialID: cq.ID, SetIndex: -1, Reason: UnmetNoCandidate}}
	}
	// §6.1: multiple defaults to false — exactly one presentation per query.
	if len(cands) > 1 && !cq.Multiple {
		return false, nil, []Unmet{{CredentialID: cq.ID, SetIndex: -1, Reason: UnmetMultiple}}
	}
	var used []string
	for i := range cands {
		reason, paths := candidateSatisfies(cq, &cands[i])
		if reason != "" {
			return false, nil, []Unmet{{CredentialID: cq.ID, SetIndex: -1, Reason: reason, Paths: paths}}
		}
		used = mergePaths(used, paths)
	}
	return true, used, nil
}

func candidateSatisfies(cq *CredentialQuery, cand *Candidate) (UnmetReason, []string) {
	if cand.Format != cq.Format {
		return UnmetFormat, nil
	}
	if !metaMatches(cq, cand) {
		return UnmetMeta, nil
	}
	// §6.1: require_cryptographic_holder_binding defaults to true.
	if cq.HolderBindingRequired() && !cand.HolderBound {
		return UnmetHolderBinding, nil
	}
	if !authorityMatches(cq.TrustedAuthorities, cand.IssuerAuthority) {
		return UnmetAuthority, nil
	}
	used, failed, ok := claimsSatisfied(cq, cand)
	if !ok {
		return UnmetClaims, failed
	}
	return "", used
}

// metaMatches applies the format-specific meta parameters
// (OID4VP Annex B.2.3 doctype_value / B.3.5 vct_values).
func metaMatches(cq *CredentialQuery, cand *Candidate) bool {
	if cq.Meta == nil {
		return false // Validate() rejects this; fail closed on contract breach
	}
	switch cq.Format {
	case FormatMdoc:
		return cand.DoctypeOrVCT == cq.Meta.DoctypeValue
	case FormatSDJWT:
		for _, vct := range cq.Meta.VCTValues {
			if cand.DoctypeOrVCT == vct {
				return true
			}
		}
	}
	return false
}

// claimsSatisfied applies OID4VP §6.4.1 to one candidate.
func claimsSatisfied(cq *CredentialQuery, cand *Candidate) (used, failed []string, ok bool) {
	if len(cq.Claims) == 0 {
		// §6.4.1: claims absent — only mandatory-to-present claims are
		// returned; no claim-level constraint. Record what was disclosed.
		return disclosedPaths(cq.Format, cand.Claims), nil, true
	}
	if len(cq.ClaimSets) == 0 {
		// §6.4.1: claims present, claim_sets absent — all listed claims.
		for i := range cq.Claims {
			c := &cq.Claims[i]
			if claimOK(cq.Format, c, cand.Claims) {
				used = append(used, c.Path.String())
			} else {
				failed = append(failed, c.Path.String())
			}
		}
		if len(failed) > 0 {
			return nil, failed, false
		}
		return used, nil, true
	}
	// §6.4.1: both present — options in preference order; first satisfiable
	// option wins.
	byID := make(map[string]*ClaimsQuery, len(cq.Claims))
	for i := range cq.Claims {
		byID[cq.Claims[i].ID] = &cq.Claims[i]
	}
	for _, set := range cq.ClaimSets {
		var paths []string
		good := true
		for _, id := range set {
			c := byID[id] // existence guaranteed by Validate()
			if c == nil || !claimOK(cq.Format, c, cand.Claims) {
				good = false
				break
			}
			paths = append(paths, c.Path.String())
		}
		if good {
			return paths, nil, true
		}
	}
	// Report the preferred (first) option as failure detail — paths only.
	for _, id := range cq.ClaimSets[0] {
		if c := byID[id]; c != nil {
			failed = append(failed, c.Path.String())
		}
	}
	return nil, failed, false
}

// claimOK: one claims query against one candidate (§6.3: with values, at
// least one selected claim must equal one of the requested values).
func claimOK(format string, c *ClaimsQuery, claims map[string]any) bool {
	vals, err := Resolve(format, claims, c.Path)
	if err != nil || len(vals) == 0 {
		return false // fail closed, incl. structural misuse
	}
	if len(c.Values) == 0 {
		return true
	}
	for _, v := range vals {
		for _, qv := range c.Values {
			if valueEqual(qv, v) {
				return true
			}
		}
	}
	return false
}

// disclosedPaths enumerates the claim paths present in a candidate — used
// for reporting when the query has no claims member. Arrays are reported as
// leaves.
func disclosedPaths(format string, claims map[string]any) []string {
	var out []string
	if format == FormatMdoc {
		for ns, elems := range claims {
			m, ok := elems.(map[string]any)
			if !ok {
				continue
			}
			for el := range m {
				out = append(out, NewPath(Key(ns), Key(el)).String())
			}
		}
	} else {
		walkLeaves(claims, nil, &out)
	}
	sort.Strings(out)
	return out
}

func walkLeaves(node map[string]any, prefix ClaimPath, out *[]string) {
	for k, v := range node {
		p := append(append(ClaimPath{}, prefix...), Key(k))
		if m, ok := v.(map[string]any); ok {
			walkLeaves(m, p, out)
			continue
		}
		*out = append(*out, p.String())
	}
}

func mergePaths(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	var out []string
	for _, s := range append(a, b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// setsSatisfied applies OID4VP §6.4.2.
func (q *Query) setsSatisfied(sat map[string]bool, res *MatchResult) bool {
	if len(q.CredentialSets) == 0 {
		// §6.4.2: credential_sets absent — every credential query required.
		for i := range q.Credentials {
			if !sat[q.Credentials[i].ID] {
				return false
			}
		}
		return true
	}
	ok := true
	for i := range q.CredentialSets {
		set := &q.CredentialSets[i]
		matched := false
		for _, opt := range set.Options {
			all := true
			for _, id := range opt {
				if !sat[id] {
					all = false
					break
				}
			}
			if all {
				matched = true
				break
			}
		}
		if !matched && set.IsRequired() {
			res.Unmet = append(res.Unmet, Unmet{SetIndex: i, Reason: UnmetSet})
			ok = false
		}
	}
	// Recorded interpretation (WP-05 Decisions, Step 6): with
	// credential_sets present, queries not referenced by any set are
	// optional.
	return ok
}

// valueEqual compares a query value (§6.3: string, integer, boolean —
// json.Number after Parse) with a claim value from a verified credential
// (JSON decode: float64/json.Number; CBOR decode: int64/uint64).
func valueEqual(queryVal, claimVal any) bool {
	switch qv := queryVal.(type) {
	case string:
		cv, ok := claimVal.(string)
		return ok && cv == qv
	case bool:
		cv, ok := claimVal.(bool)
		return ok && cv == qv
	default:
		qn, ok := toInt64(queryVal)
		if !ok {
			return false
		}
		cn, ok := toInt64(claimVal)
		return ok && qn == cn
	}
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case float64:
		if n != math.Trunc(n) {
			return 0, false
		}
		return int64(n), true
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 64)
		return i, err == nil
	default:
		return 0, false
	}
}
