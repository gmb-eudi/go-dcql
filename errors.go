package dcql

import "errors"

var (
	// ErrParse wraps syntactic failures of Parse (malformed JSON, unknown
	// members, bad path elements). Services map it to err:credential:parse
	// or a 400 at the management boundary.
	ErrParse = errors.New("dcql: parse")
	// ErrInvalid wraps semantic failures of Validate; every joined entry is
	// a *ValidationError with a position.
	// Resolve also wraps structural misuse (e.g. malformed mdoc paths,
	// unsupported formats) in ErrInvalid, without positions.
	ErrInvalid = errors.New("dcql: invalid query")
)

// ValidationError pinpoints one violation, e.g. Pos
// "credentials[0].claims[1].path". Never contains claim values (hard rule 3).
type ValidationError struct {
	Pos string
	Msg string
}

func (e *ValidationError) Error() string { return "dcql: " + e.Pos + ": " + e.Msg }

// Is reports whether this error wraps ErrInvalid.
func (e *ValidationError) Is(target error) bool { return target == ErrInvalid }
