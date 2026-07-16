package dcql_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

// [OID4VP §7] non-normative example object.
func sdjwtClaims() map[string]any {
	return map[string]any{
		"name": "Arthur Dent",
		"address": map[string]any{
			"street_address": "42 Market Street",
			"locality":       "Milliways",
			"postal_code":    "12345",
		},
		"degrees": []any{
			map[string]any{"type": "Bachelor of Science", "university": "University of Betelgeuse"},
			map[string]any{"type": "Master of Science", "university": "University of Betelgeuse"},
		},
		"nationalities": []any{"British", "Betelgeusian"},
	}
}

func TestResolveSDJWT(t *testing.T) {
	tests := []struct {
		name string
		path dcql.ClaimPath
		want []any
	}{
		{"top-level string", dcql.NewPath(dcql.Key("name")), []any{"Arthur Dent"}},
		{"nested object", dcql.NewPath(dcql.Key("address"), dcql.Key("street_address")), []any{"42 Market Street"}},
		{"whole object", dcql.NewPath(dcql.Key("address")), []any{sdjwtClaims()["address"]}},
		{"wildcard over array (§7: null selects all elements)", dcql.NewPath(dcql.Key("degrees"), dcql.Wildcard(), dcql.Key("type")), []any{"Bachelor of Science", "Master of Science"}},
		{"array index", dcql.NewPath(dcql.Key("nationalities"), dcql.Index(1)), []any{"Betelgeusian"}},
		{"missing key selects nothing", dcql.NewPath(dcql.Key("no_such")), nil},
		{"index out of bounds selects nothing", dcql.NewPath(dcql.Key("nationalities"), dcql.Index(9)), nil},
		{"wildcard on non-array selects nothing", dcql.NewPath(dcql.Key("name"), dcql.Wildcard()), nil},
		{"key into non-object selects nothing", dcql.NewPath(dcql.Key("name"), dcql.Key("x")), nil},
		{"index into non-array selects nothing", dcql.NewPath(dcql.Key("address"), dcql.Index(0)), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dcql.Resolve(dcql.FormatSDJWT, sdjwtClaims(), tt.path)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Resolve(%s) = %#v, want %#v", tt.path, got, tt.want)
			}
		})
	}
}

func mdocClaims() map[string]any {
	return map[string]any{
		"org.iso.18013.5.1": map[string]any{
			"family_name":        "Dent",
			"driving_privileges": []any{map[string]any{"vehicle_category_code": "B"}},
		},
	}
}

func TestResolveMdoc(t *testing.T) {
	got, err := dcql.Resolve(dcql.FormatMdoc, mdocClaims(), dcql.NewPath(dcql.Key("org.iso.18013.5.1"), dcql.Key("family_name")))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []any{"Dent"}) {
		t.Errorf("got %#v", got)
	}
	for name, path := range map[string]dcql.ClaimPath{
		"missing namespace": dcql.NewPath(dcql.Key("org.iso.99"), dcql.Key("family_name")),
		"missing element":   dcql.NewPath(dcql.Key("org.iso.18013.5.1"), dcql.Key("eye_colour")),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := dcql.Resolve(dcql.FormatMdoc, mdocClaims(), path)
			if err != nil || got != nil {
				t.Errorf("got %#v, %v; want nil, nil", got, err)
			}
		})
	}
	// [OID4VP §7.2]: structural misuse is an error, not an empty result.
	for name, path := range map[string]dcql.ClaimPath{
		"one element":    dcql.NewPath(dcql.Key("org.iso.18013.5.1")),
		"three elements": dcql.NewPath(dcql.Key("a"), dcql.Key("b"), dcql.Key("c")),
		"index element":  dcql.NewPath(dcql.Key("org.iso.18013.5.1"), dcql.Index(0)),
		"wildcard":       dcql.NewPath(dcql.Key("org.iso.18013.5.1"), dcql.Wildcard()),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := dcql.Resolve(dcql.FormatMdoc, mdocClaims(), path); !errors.Is(err, dcql.ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestResolveNegativeIndexRejected(t *testing.T) {
	_, err := dcql.Resolve(dcql.FormatSDJWT, sdjwtClaims(), dcql.NewPath(dcql.Key("nationalities"), dcql.Index(-1)))
	if !errors.Is(err, dcql.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}

func TestResolveUnknownFormatRejected(t *testing.T) {
	_, err := dcql.Resolve("ldp_vc", sdjwtClaims(), dcql.NewPath(dcql.Key("name")))
	if !errors.Is(err, dcql.ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
}
