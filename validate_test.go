package dcql_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

func loadQuery(t *testing.T, dir, file string) *dcql.Query {
	t.Helper()
	//nolint:gosec // G304: path comes from a fixed local testdata glob, not external input
	raw, err := os.ReadFile(filepath.Join("testdata", dir, file))
	if err != nil {
		t.Fatal(err)
	}
	q, err := dcql.Parse(raw)
	if err != nil {
		t.Fatalf("corpus file must parse: %v", err)
	}
	return q
}

func TestValidateValidCorpus(t *testing.T) {
	files, err := filepath.Glob("testdata/valid/*.json")
	if err != nil || len(files) == 0 {
		t.Fatal("no valid corpus")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			if err := loadQuery(t, "valid", filepath.Base(f)).Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

// Every invalid file rejected with a positioned error.
func TestValidateInvalidCorpus(t *testing.T) {
	tests := []struct{ file, wantPos string }{
		{"empty-credentials.json", "credentials"},
		{"dup-credential-id.json", "credentials[1].id"},
		{"bad-id-charset.json", "credentials[0].id"},
		{"missing-meta.json", "credentials[0].meta"},
		{"meta-format-mismatch.json", "credentials[0].meta"},
		{"unsupported-format.json", "credentials[0].format"},
		{"mdoc-path-3-elements.json", "credentials[0].claims[0].path"},
		{"mdoc-path-nonstring.json", "credentials[0].claims[0].path"},
		{"claim-sets-without-claims.json", "credentials[0].claim_sets"},
		{"claim-sets-unknown-ref.json", "credentials[0].claim_sets[0]"},
		{"claims-missing-id.json", "credentials[0].claims[1].id"},
		{"unknown-authority-type.json", "credentials[0].trusted_authorities[0].type"},
		{"credential-sets-unknown-ref.json", "credential_sets[0].options[1]"},
		{"values-object.json", "credentials[0].claims[0].values[0]"},
	}
	seen := map[string]bool{}
	for _, tt := range tests {
		seen[tt.file] = true
		t.Run(tt.file, func(t *testing.T) {
			err := loadQuery(t, "invalid", tt.file).Validate()
			if !errors.Is(err, dcql.ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
			if !strings.Contains(err.Error(), tt.wantPos) {
				t.Errorf("error %q lacks position %q", err.Error(), tt.wantPos)
			}
		})
	}
	// keep the corpus and this table in lockstep
	files, _ := filepath.Glob("testdata/invalid/*.json")
	for _, f := range files {
		if !seen[filepath.Base(f)] {
			t.Errorf("corpus file %s has no table entry", f)
		}
	}
}

func TestValidateRejectsNegativeProgrammaticIndex(t *testing.T) {
	q := &dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "a", Format: dcql.FormatSDJWT,
		Meta:   &dcql.Meta{VCTValues: []string{"v"}},
		Claims: []dcql.ClaimsQuery{{Path: dcql.NewPath(dcql.Key("x"), dcql.Index(-1))}},
	}}}
	err := q.Validate()
	if !errors.Is(err, dcql.ErrInvalid) || !strings.Contains(err.Error(), "credentials[0].claims[0].path") {
		t.Fatalf("err = %v, want positioned ErrInvalid", err)
	}
}
