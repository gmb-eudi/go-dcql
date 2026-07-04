package dcql

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// ClaimPath is an OID4VP §7 claims path pointer: a non-empty array whose
// elements select object keys (string), array indices (non-negative
// integer), or all elements of an array (null).
type ClaimPath []PathElement

// PathKind denotes the type of a path element.
type PathKind uint8

const (
	// KindKey denotes an object key path element.
	KindKey PathKind = iota
	// KindIndex denotes an array index path element.
	KindIndex
	// KindWildcard denotes a wildcard (array all) path element.
	KindWildcard
)

// PathElement is one component of a ClaimPath.
type PathElement struct {
	Key   string // set when Kind == KindKey
	Index int    // set when Kind == KindIndex
	Kind  PathKind
}

// Key constructs a key path element.
func Key(s string) PathElement { return PathElement{Kind: KindKey, Key: s} }

// Index constructs an index path element.
func Index(i int) PathElement { return PathElement{Kind: KindIndex, Index: i} }

// Wildcard constructs a wildcard path element.
func Wildcard() PathElement { return PathElement{Kind: KindWildcard} }

// NewPath constructs a ClaimPath from path elements.
func NewPath(elems ...PathElement) ClaimPath { return ClaimPath(elems) }

// UnmarshalJSON enforces §7 syntax: string | non-negative integer | null.
func (p *ClaimPath) UnmarshalJSON(b []byte) error {
	var raw []any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return fmt.Errorf("path must be a non-empty array (OID4VP §6.3)")
	}
	out := make(ClaimPath, 0, len(raw))
	for i, e := range raw {
		switch v := e.(type) {
		case nil:
			out = append(out, Wildcard())
		case string:
			out = append(out, Key(v))
		case json.Number:
			n, err := strconv.Atoi(string(v))
			if err != nil || n < 0 {
				return fmt.Errorf("path[%d]: array index must be a non-negative integer (OID4VP §7)", i)
			}
			out = append(out, Index(n))
		default:
			return fmt.Errorf("path[%d]: element must be string, non-negative integer, or null (OID4VP §7)", i)
		}
	}
	*p = out
	return nil
}

// MarshalJSON encodes the path as a JSON array.
func (p ClaimPath) MarshalJSON() ([]byte, error) {
	raw := make([]any, len(p))
	for i, e := range p {
		switch e.Kind {
		case KindKey:
			raw[i] = e.Key
		case KindIndex:
			raw[i] = e.Index
		case KindWildcard:
			raw[i] = nil
		default:
			return nil, fmt.Errorf("dcql: invalid path element kind %d", e.Kind)
		}
	}
	return json.Marshal(raw)
}

// String renders the path in its JSON form — the canonical representation
// used in MatchResult.ByCredential, Unmet.Paths, and scope offenses.
func (p ClaimPath) String() string {
	b, err := p.MarshalJSON()
	if err != nil {
		return "[invalid path]"
	}
	return string(b)
}

// Equal reports whether two paths are equal.
func (p ClaimPath) Equal(o ClaimPath) bool {
	if len(p) != len(o) {
		return false
	}
	for i := range p {
		if p[i] != o[i] {
			return false
		}
	}
	return true
}
