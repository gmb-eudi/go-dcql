package dcql

import "fmt"

// Resolve applies a claims path pointer to the claims of one credential.
// SD-JWT VC: full JSON traversal per OID4VP §7.1/§7.3 — a component that
// selects nothing resolves the whole path to no claims (empty result, nil
// error). mdoc: exactly [namespace, element] per §7.2 — any other shape is
// ErrInvalid (structural misuse, distinct from "not disclosed").
func Resolve(format string, claims map[string]any, path ClaimPath) ([]any, error) {
	switch format {
	case FormatMdoc:
		if !mdocPathOK(path) {
			return nil, fmt.Errorf("%w: mdoc claim path must be [namespace, element] (§7.2)", ErrInvalid)
		}
		ns, ok := claims[path[0].Key].(map[string]any)
		if !ok {
			return nil, nil
		}
		v, ok := ns[path[1].Key]
		if !ok {
			return nil, nil
		}
		return []any{v}, nil
	case FormatSDJWT:
		// §7.3 processing: start with the root; apply each component to every
		// currently selected element.
		cur := []any{any(claims)}
		for _, el := range path {
			var next []any
			for _, node := range cur {
				switch el.Kind {
				case KindKey:
					if m, ok := node.(map[string]any); ok {
						if v, exists := m[el.Key]; exists {
							next = append(next, v)
						}
					}
				case KindIndex:
					if el.Index < 0 {
						return nil, fmt.Errorf("%w: array index must be non-negative (§7)", ErrInvalid)
					}
					if a, ok := node.([]any); ok && el.Index < len(a) {
						next = append(next, a[el.Index])
					}
				case KindWildcard:
					if a, ok := node.([]any); ok {
						next = append(next, a...)
					}
				default:
					return nil, fmt.Errorf("%w: invalid path element", ErrInvalid)
				}
			}
			if len(next) == 0 {
				return nil, nil
			}
			cur = next
		}
		return cur, nil
	default:
		return nil, fmt.Errorf("%w: unsupported format %q", ErrInvalid, format)
	}
}
