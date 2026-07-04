package dcql_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

func sdjwtCand(id, vct string, claims map[string]any) dcql.Candidate {
	return dcql.Candidate{QueryCredID: id, Format: dcql.FormatSDJWT, DoctypeOrVCT: vct, Claims: claims, HolderBound: true}
}

func mdocCand(id, doctype string, claims map[string]any) dcql.Candidate {
	return dcql.Candidate{QueryCredID: id, Format: dcql.FormatMdoc, DoctypeOrVCT: doctype, Claims: claims, HolderBound: true}
}

func pidClaims() map[string]any {
	return map[string]any{"given_name": "Arthur", "family_name": "Dent", "age_over_18": true}
}

// T-05.4 acceptance: every valid-corpus (§6-example) query has a passing and
// a failing candidate-set test.
func TestMatchCorpus(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		cands   []dcql.Candidate
		want    bool
		reasons []dcql.UnmetReason
	}{
		{
			"sdjwt basic pass", "sdjwt-basic.json",
			[]dcql.Candidate{sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
				"last_name": "Dent", "first_name": "Arthur",
				"address": map[string]any{"street_address": "42 Market Street"},
			})},
			true, nil,
		},
		{
			"sdjwt basic fail: missing claim", "sdjwt-basic.json",
			[]dcql.Candidate{sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
				"last_name": "Dent", "first_name": "Arthur",
			})},
			false, []dcql.UnmetReason{dcql.UnmetClaims},
		},
		{
			"sdjwt basic fail: wrong vct", "sdjwt-basic.json",
			[]dcql.Candidate{sdjwtCand("my_credential", "https://other.example.com/vct", pidClaims())},
			false, []dcql.UnmetReason{dcql.UnmetMeta},
		},
		{
			"mdoc pass", "mdoc-mdl.json",
			[]dcql.Candidate{mdocCand("mdl", "org.iso.18013.5.1.mDL", mdocClaims())},
			true, nil,
		},
		{
			"mdoc fail: wrong doctype", "mdoc-mdl.json",
			[]dcql.Candidate{mdocCand("mdl", "org.iso.18013.5.1.aamva", mdocClaims())},
			false, []dcql.UnmetReason{dcql.UnmetMeta},
		},
		{
			"credential_sets: sdjwt option satisfies", "credential-sets.json",
			[]dcql.Candidate{sdjwtCand("pid_sdjwt", "urn:eudi:pid:1", pidClaims())},
			true, nil,
		},
		{
			"credential_sets: mdoc option satisfies", "credential-sets.json",
			[]dcql.Candidate{mdocCand("pid_mdoc", "eu.europa.ec.eudi.pid.1", map[string]any{
				"eu.europa.ec.eudi.pid.1": map[string]any{"given_name": "Arthur", "family_name": "Dent"},
			})},
			true, nil,
		},
		{
			"credential_sets: only optional set satisfied", "credential-sets.json",
			[]dcql.Candidate{sdjwtCand("reward_card", "https://loyalty.example.com/card", map[string]any{"points": float64(9000)})},
			false, []dcql.UnmetReason{dcql.UnmetNoCandidate, dcql.UnmetSet},
		},
		{
			"claim_sets: preferred option", "claim-sets.json",
			[]dcql.Candidate{sdjwtCand("pid", "urn:eudi:pid:1", map[string]any{
				"last_name": "Dent", "locality": "Milliways", "region": "Betelgeuse", "date_of_birth": "1980-01-01",
			})},
			true, nil,
		},
		{
			"claim_sets: fallback option", "claim-sets.json",
			[]dcql.Candidate{sdjwtCand("pid", "urn:eudi:pid:1", map[string]any{
				"last_name": "Dent", "postal_code": "12345", "date_of_birth": "1980-01-01",
			})},
			true, nil,
		},
		{
			"claim_sets: neither option", "claim-sets.json",
			[]dcql.Candidate{sdjwtCand("pid", "urn:eudi:pid:1", map[string]any{"last_name": "Dent"})},
			false, []dcql.UnmetReason{dcql.UnmetClaims},
		},
		{
			"values: matching value and int normalization", "values-and-wildcard.json",
			[]dcql.Candidate{sdjwtCand("graduate", "https://credentials.example.com/graduate", map[string]any{
				"degrees":       []any{map[string]any{"type": "Bachelor of Science"}},
				"nationalities": []any{"British", "Betelgeusian"},
				"age_over_18":   true,
				"reward_level":  float64(3), // JSON-decoded number vs query integer 3
			})},
			true, nil,
		},
		{
			"values: wrong value", "values-and-wildcard.json",
			[]dcql.Candidate{sdjwtCand("graduate", "https://credentials.example.com/graduate", map[string]any{
				"degrees":       []any{map[string]any{"type": "Master of Arts"}},
				"nationalities": []any{"British", "Betelgeusian"},
				"age_over_18":   true,
				"reward_level":  float64(3),
			})},
			false, []dcql.UnmetReason{dcql.UnmetClaims},
		},
		{
			"no candidate at all", "sdjwt-basic.json",
			nil,
			false, []dcql.UnmetReason{dcql.UnmetNoCandidate},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := loadQuery(t, "valid", tt.file)
			if err := q.Validate(); err != nil {
				t.Fatal(err)
			}
			res := q.Match(tt.cands)
			if res.Satisfied != tt.want {
				t.Fatalf("Satisfied = %v, want %v (unmet: %+v)", res.Satisfied, tt.want, res.Unmet)
			}
			for _, want := range tt.reasons {
				found := false
				for _, u := range res.Unmet {
					if u.Reason == want {
						found = true
					}
				}
				if !found {
					t.Errorf("Unmet lacks reason %q: %+v", want, res.Unmet)
				}
			}
		})
	}
}

func TestMatchRecordsUsedPaths(t *testing.T) {
	q := loadQuery(t, "valid", "sdjwt-basic.json")
	res := q.Match([]dcql.Candidate{sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
		"last_name": "Dent", "first_name": "Arthur",
		"address": map[string]any{"street_address": "42 Market Street"},
	})})
	want := []string{`["last_name"]`, `["first_name"]`, `["address","street_address"]`}
	got := res.ByCredential["my_credential"]
	if len(got) != len(want) {
		t.Fatalf("ByCredential = %v, want %v", got, want)
	}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("ByCredential %v lacks %q", got, w)
		}
	}
}

func TestMatchMultiple(t *testing.T) {
	q := loadQuery(t, "valid", "sdjwt-basic.json")
	c := sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
		"last_name": "Dent", "first_name": "Arthur",
		"address": map[string]any{"street_address": "42 Market Street"},
	})
	// §6.1: multiple defaults to false — two presentations for one query fail.
	res := q.Match([]dcql.Candidate{c, c})
	if res.Satisfied {
		t.Fatal("Satisfied = true with duplicate candidates and multiple=false")
	}
	found := false
	for _, u := range res.Unmet {
		if u.Reason == dcql.UnmetMultiple {
			found = true
		}
	}
	if !found {
		t.Errorf("Unmet lacks %q: %+v", dcql.UnmetMultiple, res.Unmet)
	}
}

// §6.1: require_cryptographic_holder_binding defaults to true.
func TestMatchHolderBindingGate(t *testing.T) {
	q := loadQuery(t, "valid", "sdjwt-basic.json")
	c := sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
		"last_name": "Dent", "first_name": "Arthur",
		"address": map[string]any{"street_address": "42 Market Street"},
	})
	c.HolderBound = false
	res := q.Match([]dcql.Candidate{c})
	if res.Satisfied {
		t.Fatal("Satisfied = true without holder binding")
	}
	// explicit opt-out
	f := false
	q.Credentials[0].RequireCryptographicHolderBinding = &f
	if res := q.Match([]dcql.Candidate{c}); !res.Satisfied {
		t.Fatalf("Satisfied = false with binding requirement disabled: %+v", res.Unmet)
	}
}

// Pipeline step 8: no over-disclosure accepted silently — a candidate
// answering an unknown query id fails the match.
func TestMatchUnknownQueryID(t *testing.T) {
	q := loadQuery(t, "valid", "sdjwt-basic.json")
	good := sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
		"last_name": "Dent", "first_name": "Arthur",
		"address": map[string]any{"street_address": "42 Market Street"},
	})
	rogue := sdjwtCand("not_in_query", "urn:eudi:pid:1", pidClaims())
	res := q.Match([]dcql.Candidate{good, rogue})
	if res.Satisfied {
		t.Fatal("Satisfied = true despite over-disclosed credential")
	}
	found := false
	for _, u := range res.Unmet {
		if u.Reason == dcql.UnmetUnknownQuery && u.CredentialID == "not_in_query" {
			found = true
		}
	}
	if !found {
		t.Errorf("Unmet lacks unknown-credential-query entry: %+v", res.Unmet)
	}
}

// Claims absent (reward_card): meta-only match; disclosed paths recorded.
func TestMatchClaimsAbsent(t *testing.T) {
	q := loadQuery(t, "valid", "credential-sets.json")
	res := q.Match([]dcql.Candidate{
		sdjwtCand("pid_sdjwt", "urn:eudi:pid:1", pidClaims()),
		sdjwtCand("reward_card", "https://loyalty.example.com/card", map[string]any{"points": float64(9000)}),
	})
	if !res.Satisfied {
		t.Fatalf("Satisfied = false: %+v", res.Unmet)
	}
	if got := res.ByCredential["reward_card"]; !reflect.DeepEqual(got, []string{`["points"]`}) {
		t.Errorf("reward_card paths = %v, want [\"points\"]", got)
	}
}

// Unmet must never carry claim values (hard rule 3 / WP-05 decision).
func TestUnmetCarriesPathsNotValues(t *testing.T) {
	q := loadQuery(t, "valid", "values-and-wildcard.json")
	res := q.Match([]dcql.Candidate{sdjwtCand("graduate", "https://credentials.example.com/graduate", map[string]any{
		"degrees":       []any{map[string]any{"type": "SECRET-DEGREE-VALUE"}},
		"nationalities": []any{"a", "b"},
		"age_over_18":   true,
		"reward_level":  float64(3),
	})})
	if res.Satisfied {
		t.Fatal("expected unsatisfied")
	}
	for _, u := range res.Unmet {
		for _, p := range u.Paths {
			if strings.Contains(p, "SECRET-DEGREE-VALUE") {
				t.Fatalf("Unmet path %q leaks a claim value", p)
			}
		}
	}
}

// Defense in depth: Match must never panic on a query that has not passed
// Validate() (e.g. nil Meta) — it should simply fail closed.
func TestMatchToleratesUnvalidatedQuery(t *testing.T) {
	q := &dcql.Query{Credentials: []dcql.CredentialQuery{{ID: "x", Format: dcql.FormatMdoc}}} // nil Meta
	res := q.Match([]dcql.Candidate{{QueryCredID: "x", Format: dcql.FormatMdoc}})
	if res.Satisfied {
		t.Fatal("nil-Meta query must not be satisfied")
	}
}
