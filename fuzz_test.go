package dcql_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gmb-eudi/go-dcql"
)

// Hard rule 5: Parse+Validate must never panic on malformed input.
func FuzzParse(f *testing.F) {
	for _, dir := range []string{"testdata/valid", "testdata/invalid"} {
		files, err := filepath.Glob(dir + "/*.json")
		if err != nil {
			f.Fatal(err)
		}
		for _, file := range files {
			//nolint:gosec // G304: path comes from a fixed local testdata glob, not external input
			raw, err := os.ReadFile(file)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(raw)
		}
	}
	f.Add([]byte(`{"credentials":[{"id":"a","format":"dc+sd-jwt","meta":{"vct_values":["v"]},"claims":[{"path":["a",null,0]}]}]}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		q, err := dcql.Parse(data)
		if err == nil {
			_ = q.Validate() // must not panic
		}
	})
}
