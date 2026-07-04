package dcql_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

func TestPresetsValidate(t *testing.T) {
	for name, preset := range map[string]*dcql.Query{
		"pid-age-over-18":        dcql.PresetPIDAgeOver18(),
		"pid-full":               dcql.PresetPIDFull(),
		"mdl-driving-privileges": dcql.PresetMDLDrivingPrivileges(),
	} {
		t.Run(name, func(t *testing.T) {
			if err := preset.Validate(); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

// T-05.7: presets appear in testdata — golden files must stay semantically
// identical to the constructors (compared via Parse, not bytes).
func TestPresetsMatchGoldenFiles(t *testing.T) {
	for file, preset := range map[string]*dcql.Query{
		"pid-age-over-18.json":        dcql.PresetPIDAgeOver18(),
		"pid-full.json":               dcql.PresetPIDFull(),
		"mdl-driving-privileges.json": dcql.PresetMDLDrivingPrivileges(),
	} {
		t.Run(file, func(t *testing.T) {
			//nolint:gosec // G304: path comes from a fixed local testdata glob, not external input
			raw, err := os.ReadFile(filepath.Join("testdata", "presets", file))
			if err != nil {
				t.Fatal(err)
			}
			golden, err := dcql.Parse(raw)
			if err != nil {
				t.Fatalf("golden must parse: %v", err)
			}
			out, err := json.Marshal(preset)
			if err != nil {
				t.Fatal(err)
			}
			normalized, err := dcql.Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(golden, normalized) {
				t.Errorf("preset and golden diverge:\ngolden=%#v\npreset=%#v", golden, normalized)
			}
		})
	}
}

func TestPresetAgeOver18Matches(t *testing.T) {
	q := dcql.PresetPIDAgeOver18()
	c := mdocCand("pid_mdoc", "eu.europa.ec.eudi.pid.1", map[string]any{
		"eu.europa.ec.eudi.pid.1": map[string]any{"age_over_18": true},
	})
	if res := q.Match([]dcql.Candidate{c}); !res.Satisfied {
		t.Fatalf("mdoc age_over_18=true: %+v", res.Unmet)
	}
	under := mdocCand("pid_mdoc", "eu.europa.ec.eudi.pid.1", map[string]any{
		"eu.europa.ec.eudi.pid.1": map[string]any{"age_over_18": false},
	})
	if res := q.Match([]dcql.Candidate{under}); res.Satisfied {
		t.Fatal("age_over_18=false must not satisfy (values gate)")
	}
	sdjwt := sdjwtCand("pid_sdjwt", "urn:eudi:pid:1", map[string]any{"age_over_18": true})
	if res := q.Match([]dcql.Candidate{sdjwt}); !res.Satisfied {
		t.Fatalf("sd-jwt option: %+v", res.Unmet)
	}
}
