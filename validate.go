package dcql

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// Validate checks the semantic rules of OID4VP §6/§7 and returns all
// violations joined; each entry is a *ValidationError with a position.
func (q *Query) Validate() error {
	var errs []error
	add := func(pos, format string, args ...any) {
		errs = append(errs, &ValidationError{Pos: pos, Msg: fmt.Sprintf(format, args...)})
	}
	if len(q.Credentials) == 0 {
		add("credentials", "must be a non-empty array (OID4VP §6)")
	}
	ids := map[string]bool{}
	for i := range q.Credentials {
		c := &q.Credentials[i]
		pos := fmt.Sprintf("credentials[%d]", i)
		if !validID(c.ID) {
			add(pos+".id", "must be a non-empty alphanumeric/underscore/hyphen string (§6.1)")
		} else if ids[c.ID] {
			add(pos+".id", "duplicate id %q (§6.1: ids unique within credentials)", c.ID)
		}
		ids[c.ID] = true
		validateFormatMeta(c, pos, add)
		validateClaims(c, pos, add)
		validateAuthorities(c, pos, add)
	}
	for i := range q.CredentialSets {
		s := &q.CredentialSets[i]
		pos := fmt.Sprintf("credential_sets[%d]", i)
		if len(s.Options) == 0 {
			add(pos+".options", "must be a non-empty array (§6.2)")
		}
		for j, opt := range s.Options {
			opos := fmt.Sprintf("%s.options[%d]", pos, j)
			if len(opt) == 0 {
				add(opos, "option must be a non-empty array of credential ids (§6.2)")
			}
			for _, id := range opt {
				if !ids[id] {
					add(opos, "references unknown credential id %q (§6.2)", id)
				}
			}
		}
	}
	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

func validateFormatMeta(c *CredentialQuery, pos string, add func(string, string, ...any)) {
	switch c.Format {
	case FormatSDJWT:
		if c.Meta == nil || len(c.Meta.VCTValues) == 0 {
			add(pos+".meta", "vct_values required for dc+sd-jwt (Annex B.3.5; §6.1: meta REQUIRED)")
		}
		if c.Meta != nil && c.Meta.DoctypeValue != "" {
			add(pos+".meta", "doctype_value not allowed for dc+sd-jwt")
		}
	case FormatMdoc:
		if c.Meta == nil || c.Meta.DoctypeValue == "" {
			add(pos+".meta", "doctype_value required for mso_mdoc (Annex B.2.3; §6.1: meta REQUIRED)")
		}
		if c.Meta != nil && len(c.Meta.VCTValues) > 0 {
			add(pos+".meta", "vct_values not allowed for mso_mdoc")
		}
	default:
		add(pos+".format", "unsupported format %q — mso_mdoc or dc+sd-jwt (HAIP 1.0)", c.Format)
	}
}

func validateClaims(c *CredentialQuery, pos string, add func(string, string, ...any)) {
	if c.Claims != nil && len(c.Claims) == 0 {
		add(pos+".claims", "must be non-empty when present (§6.1)")
	}
	claimIDs := map[string]bool{}
	for j := range c.Claims {
		cq := &c.Claims[j]
		cpos := fmt.Sprintf("%s.claims[%d]", pos, j)
		if len(cq.Path) == 0 {
			add(cpos+".path", "must be a non-empty claims path pointer (§6.3)")
		}
		if c.Format == FormatMdoc && !mdocPathOK(cq.Path) {
			add(cpos+".path", "mdoc path must be exactly [namespace, element], both strings (§7.2)")
		}
		for k := range cq.Path {
			if cq.Path[k].Kind == KindIndex && cq.Path[k].Index < 0 {
				add(cpos+".path", "array index must be non-negative (§7)")
			}
		}
		if len(c.ClaimSets) > 0 && cq.ID == "" {
			add(cpos+".id", "id required when claim_sets is present (§6.3)")
		}
		if cq.ID != "" {
			if !validID(cq.ID) {
				add(cpos+".id", "must be alphanumeric/underscore/hyphen (§6.3)")
			} else if claimIDs[cq.ID] {
				add(cpos+".id", "duplicate claim id %q", cq.ID)
			}
			claimIDs[cq.ID] = true
		}
		for k, v := range cq.Values {
			if !validClaimValue(v) {
				add(fmt.Sprintf("%s.values[%d]", cpos, k), "must be a string, integer, or boolean (§6.3)")
			}
		}
	}
	if len(c.ClaimSets) > 0 && len(c.Claims) == 0 {
		add(pos+".claim_sets", "must not be present when claims is absent (§6.4.1)")
	}
	for j, set := range c.ClaimSets {
		spos := fmt.Sprintf("%s.claim_sets[%d]", pos, j)
		if len(set) == 0 {
			add(spos, "claim set must be non-empty (§6.1)")
		}
		for _, id := range set {
			if !claimIDs[id] {
				add(spos, "references unknown claim id %q (§6.1)", id)
			}
		}
	}
}

func validateAuthorities(c *CredentialQuery, pos string, add func(string, string, ...any)) {
	if c.TrustedAuthorities != nil && len(c.TrustedAuthorities) == 0 {
		add(pos+".trusted_authorities", "must be non-empty when present (§6.1)")
	}
	for j := range c.TrustedAuthorities {
		ta := &c.TrustedAuthorities[j]
		tpos := fmt.Sprintf("%s.trusted_authorities[%d]", pos, j)
		switch ta.Type {
		case AuthorityTypeAKI, AuthorityTypeETSITL, AuthorityTypeOpenIDFederation:
		default:
			// T-05.5 acceptance: unknown type = query invalid, no fall-through.
			add(tpos+".type", "unknown trusted authority type %q (§6.1.1)", ta.Type)
		}
		if len(ta.Values) == 0 {
			add(tpos+".values", "must be a non-empty array of strings (§6.1.1)")
		}
		for k, v := range ta.Values {
			if v == "" {
				add(fmt.Sprintf("%s.values[%d]", tpos, k), "must be a non-empty string (§6.1.1)")
			}
		}
	}
}

// validID: §6.1/§6.3 — non-empty; alphanumeric, underscore, hyphen.
func validID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// mdocPathOK: §7.2 — exactly two elements, namespace and element, both strings.
func mdocPathOK(p ClaimPath) bool {
	return len(p) == 2 && p[0].Kind == KindKey && p[1].Kind == KindKey
}

// validClaimValue: §6.3 — strings, integers, booleans. json.Number after
// Parse; plain Go types for programmatically built queries.
func validClaimValue(v any) bool {
	switch n := v.(type) {
	case string, bool, int, int64:
		return true
	case float64:
		return n == math.Trunc(n)
	case json.Number:
		_, err := strconv.ParseInt(string(n), 10, 64)
		return err == nil
	default:
		return false
	}
}
