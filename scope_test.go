package dcql_test

import (
	"strings"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

func pidRegistration(all bool, claims ...dcql.ClaimPath) dcql.RegisteredCredential {
	return dcql.RegisteredCredential{
		Format:         dcql.FormatSDJWT,
		DoctypesOrVCTs: []string{"urn:eudi:pid:1"},
		AllClaims:      all,
		Claims:         claims,
	}
}

func scopeQuery(t *testing.T, claims string) *dcql.Query {
	t.Helper()
	raw := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]}` + claims + `}]}`
	q, err := dcql.Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Validate(); err != nil {
		t.Fatal(err)
	}
	return q
}

func TestWithinScope(t *testing.T) {
	reg := []dcql.RegisteredCredential{pidRegistration(false,
		dcql.NewPath(dcql.Key("family_name")),
		dcql.NewPath(dcql.Key("given_name")),
		dcql.NewPath(dcql.Key("degrees"), dcql.Wildcard(), dcql.Key("type")),
	)}

	t.Run("query within registration", func(t *testing.T) {
		q := scopeQuery(t, `,"claims":[{"path":["family_name"]},{"path":["given_name"]}]`)
		ok, offenses := q.WithinScope(reg)
		if !ok || len(offenses) != 0 {
			t.Fatalf("ok=%v offenses=%v, want true, none", ok, offenses)
		}
	})

	// T-05.6 acceptance: superset query rejected with offending paths listed
	// (drives err:client:scope-exceeded).
	t.Run("superset query lists offending paths", func(t *testing.T) {
		q := scopeQuery(t, `,"claims":[{"path":["family_name"]},{"path":["birth_date"]},{"path":["nationality"]}]`)
		ok, offenses := q.WithinScope(reg)
		if ok {
			t.Fatal("ok = true for superset query")
		}
		joined := strings.Join(offenses, "\n")
		for _, want := range []string{`["birth_date"]`, `["nationality"]`} {
			if !strings.Contains(joined, want) {
				t.Errorf("offenses %v lack %s", offenses, want)
			}
		}
		if strings.Contains(joined, `["family_name"]`) {
			t.Errorf("offenses %v wrongly include the registered path", offenses)
		}
	})

	t.Run("registered wildcard covers concrete index", func(t *testing.T) {
		q := scopeQuery(t, `,"claims":[{"path":["degrees",0,"type"]}]`)
		if ok, offenses := q.WithinScope(reg); !ok {
			t.Fatalf("offenses = %v, want covered by registered wildcard", offenses)
		}
	})

	t.Run("claims absent requires all-claims registration", func(t *testing.T) {
		q := scopeQuery(t, ``)
		if ok, _ := q.WithinScope(reg); ok {
			t.Fatal("ok = true: claims-absent query against specific-claims registration")
		}
		if ok, offenses := q.WithinScope([]dcql.RegisteredCredential{pidRegistration(true)}); !ok {
			t.Fatalf("offenses = %v, want ok with AllClaims registration", offenses)
		}
	})

	t.Run("unregistered format or vct", func(t *testing.T) {
		q := scopeQuery(t, `,"claims":[{"path":["family_name"]}]`)
		mdlOnly := []dcql.RegisteredCredential{{
			Format: dcql.FormatMdoc, DoctypesOrVCTs: []string{"org.iso.18013.5.1.mDL"}, AllClaims: true,
		}}
		ok, offenses := q.WithinScope(mdlOnly)
		if ok || len(offenses) == 0 {
			t.Fatalf("ok=%v offenses=%v, want format/vct offense", ok, offenses)
		}
	})

	t.Run("query accepting unregistered vct alternative", func(t *testing.T) {
		raw := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1","urn:other:pid"]},"claims":[{"path":["family_name"]}]}]}`
		q, err := dcql.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if ok, _ := q.WithinScope(reg); ok {
			t.Fatal("ok = true although urn:other:pid is not registered")
		}
	})

	// Union semantics: claims referenced only through claim_sets still count
	// ("every claim the query could request" — WP-05 README).
	t.Run("claim_sets union checked", func(t *testing.T) {
		raw := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},
			"claims":[{"id":"a","path":["family_name"]},{"id":"b","path":["tax_id"]}],
			"claim_sets":[["a"],["a","b"]]}]}`
		q, err := dcql.Parse([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		ok, offenses := q.WithinScope(reg)
		if ok {
			t.Fatal("ok = true although tax_id (claim_sets fallback) is unregistered")
		}
		if !strings.Contains(strings.Join(offenses, "\n"), `["tax_id"]`) {
			t.Errorf("offenses %v lack tax_id path", offenses)
		}
	})
}
