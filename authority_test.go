package dcql_test

import (
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

func TestMatchTrustedAuthorities(t *testing.T) {
	base := func() dcql.Candidate {
		c := sdjwtCand("pid", "urn:eudi:pid:1", map[string]any{"family_name": "Dent"})
		return c
	}
	tests := []struct {
		name string
		ref  dcql.AuthorityRef
		want bool
	}{
		{"aki match", dcql.AuthorityRef{AKIs: []string{"s9tIpPmhxdiuNkHMEWNpYim8S8Y"}}, true},
		{"etsi_tl match (second entry, OR across entries §6.1.1)", dcql.AuthorityRef{TrustedListURIs: []string{"https://lotl.example.eu"}}, true},
		{"no reference data", dcql.AuthorityRef{}, false},
		{"wrong aki", dcql.AuthorityRef{AKIs: []string{"other-key-id"}}, false},
		{"federation id does not satisfy aki/etsi_tl entries", dcql.AuthorityRef{FederationIDs: []string{"https://fed.example.eu"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := loadQuery(t, "valid", "trusted-authorities.json")
			if err := q.Validate(); err != nil {
				t.Fatal(err)
			}
			cand := base()
			cand.IssuerAuthority = tt.ref
			res := q.Match([]dcql.Candidate{cand})
			if res.Satisfied != tt.want {
				t.Fatalf("Satisfied = %v, want %v (unmet %+v)", res.Satisfied, tt.want, res.Unmet)
			}
			if !tt.want {
				found := false
				for _, u := range res.Unmet {
					if u.Reason == dcql.UnmetAuthority {
						found = true
					}
				}
				if !found {
					t.Errorf("Unmet lacks %q: %+v", dcql.UnmetAuthority, res.Unmet)
				}
			}
		})
	}
}

// Absent trusted_authorities = no constraint.
func TestNoAuthoritiesNoConstraint(t *testing.T) {
	q := loadQuery(t, "valid", "sdjwt-basic.json")
	c := sdjwtCand("my_credential", "https://credentials.example.com/identity_credential", map[string]any{
		"last_name": "Dent", "first_name": "Arthur",
		"address": map[string]any{"street_address": "42 Market Street"},
	})
	if res := q.Match([]dcql.Candidate{c}); !res.Satisfied {
		t.Fatalf("Satisfied = false without trusted_authorities: %+v", res.Unmet)
	}
}

func TestOpenIDFederationAuthority(t *testing.T) {
	raw := []byte(`{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
		"trusted_authorities":[{"type":"openid_federation","values":["https://fed.example.eu"]}],
		"claims":[{"path":["family_name"]}]}]}`)
	q, err := dcql.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	c := sdjwtCand("pid", "urn:eudi:pid:1", map[string]any{"family_name": "Dent"})
	c.IssuerAuthority = dcql.AuthorityRef{FederationIDs: []string{"https://fed.example.eu"}}
	if res := q.Match([]dcql.Candidate{c}); !res.Satisfied {
		t.Fatalf("Satisfied = false: %+v", res.Unmet)
	}
}
