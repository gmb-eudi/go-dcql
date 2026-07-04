package dcql_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

// Every valid corpus file must parse, re-marshal, and re-parse to the same
// model (T-05.1: marshal/unmarshal golden files).
func TestParseMarshalRoundtrip(t *testing.T) {
	files, err := filepath.Glob("testdata/valid/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no valid corpus: %v", err)
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f) //nolint:gosec // G304: f comes from a fixed local testdata glob, not external input
			if err != nil {
				t.Fatal(err)
			}
			q, err := dcql.Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			out, err := json.Marshal(q)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			q2, err := dcql.Parse(out)
			if err != nil {
				t.Fatalf("re-Parse: %v", err)
			}
			if !reflect.DeepEqual(q, q2) {
				t.Errorf("roundtrip mismatch:\n first=%#v\nsecond=%#v", q, q2)
			}
		})
	}
}

// T-05.1: unknown-field rejection. Strictness is deliberate at ALL levels
// (WP-05 decision, Step 8) — this is the authoring boundary, not a wallet.
func TestParseRejectsUnknownFields(t *testing.T) {
	for name, doc := range map[string]string{
		"top-level":  `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"presentation_definition":{}}`,
		"credential": `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"purpose":"why"}]}`,
		"meta":       `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"],"extra":1}}]}`,
		"claims":     `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["x"],"intent_to_retain":true}]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := dcql.Parse([]byte(doc)); !errors.Is(err, dcql.ErrParse) {
				t.Fatalf("err = %v, want ErrParse", err)
			}
		})
	}
}

func TestParseRejectsBadPathElements(t *testing.T) {
	shell := `{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":%s}]}]}`
	for name, path := range map[string]string{
		"float-index":    `["a",1.5]`,
		"negative-index": `["a",-1]`,
		"bool-element":   `[true]`,
		"object-element": `[{"k":1}]`,
		"empty-path":     `[]`,
		"exponent":       `["a",1e2]`,
	} {
		t.Run(name, func(t *testing.T) {
			doc := []byte(strings.Replace(shell, "%s", path, 1))
			if _, err := dcql.Parse(doc); !errors.Is(err, dcql.ErrParse) {
				t.Fatalf("path %s: err = %v, want ErrParse", path, err)
			}
		})
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, doc := range [][]byte{nil, []byte(""), []byte("null"), []byte("[]"), []byte(`{"credentials":`), []byte(`{"credentials":[]} trailing`)} {
		if _, err := dcql.Parse(doc); !errors.Is(err, dcql.ErrParse) {
			t.Errorf("doc %q: err = %v, want ErrParse", doc, err)
		}
	}
}

func TestClaimPathString(t *testing.T) {
	p := dcql.NewPath(dcql.Key("degrees"), dcql.Wildcard(), dcql.Key("type"))
	if got, want := p.String(), `["degrees",null,"type"]`; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
	p2 := dcql.NewPath(dcql.Key("nationalities"), dcql.Index(1))
	if got, want := p2.String(), `["nationalities",1]`; got != want {
		t.Errorf("String() = %s, want %s", got, want)
	}
	if !p.Equal(dcql.NewPath(dcql.Key("degrees"), dcql.Wildcard(), dcql.Key("type"))) {
		t.Error("Equal() = false for identical paths")
	}
	if p.Equal(p2) {
		t.Error("Equal() = true for different paths")
	}
}

func TestDefaults(t *testing.T) {
	q, err := dcql.Parse([]byte(`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]}}],"credential_sets":[{"options":[["a"]]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	// OID4VP §6.1: require_cryptographic_holder_binding defaults true;
	// §6.2: required defaults true.
	if !q.Credentials[0].HolderBindingRequired() {
		t.Error("HolderBindingRequired() default = false, want true")
	}
	if q.Credentials[0].Multiple {
		t.Error("Multiple default = true, want false")
	}
	if !q.CredentialSets[0].IsRequired() {
		t.Error("IsRequired() default = false, want true")
	}
}
