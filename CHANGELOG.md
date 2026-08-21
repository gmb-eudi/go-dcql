# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.2

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **`Parse` now wraps the underlying cause as well as its sentinel.** The error was built as
  `fmt.Errorf("%w: %v", ErrParse, err)` — the sentinel wrapped, the cause formatted into the
  string and then unreachable. It is now `%w` for both, so a caller can ask what actually went
  wrong:

  ```go
  var syntaxErr *json.SyntaxError
  if errors.As(err, &syntaxErr) { /* malformed JSON, not a schema problem */ }
  ```

  `errors.Is(err, ErrParse)` still holds and the rendered message is byte-identical (`%v` and
  `%w` print an error the same way), so no existing caller needs to change. What is new is that
  the cause is part of the error chain.

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.
