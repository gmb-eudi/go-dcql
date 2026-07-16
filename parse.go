package dcql

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Parse parses raw into a Query. Strict at every level: unknown members are
// rejected (this is the query-AUTHORING boundary; a member
// we don't understand could silently widen disclosure. [OID4VP §6]'s "ignore
// unknown properties" targets consumers of foreign queries, i.e. wallets.)
// Numbers are kept as json.Number so claim values survive untouched.
func Parse(raw []byte) (*Query, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	var q Query
	if err := dec.Decode(&q); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrParse, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w: trailing data after query object", ErrParse)
	}
	if q.Credentials == nil && q.CredentialSets == nil {
		return nil, fmt.Errorf("%w: not a DCQL query object", ErrParse)
	}
	return &q, nil
}
