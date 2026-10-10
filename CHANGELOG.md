# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.3

**Requires Go 1.27.2.** The `go` directive moves up from 1.26.6, so a consumer on an older
toolchain will not build this version. Nothing else changed here: no source, no signature, no
message text, and the library still has no dependencies.

### Changed

- **`go` directive 1.26.6 → 1.27.2**, the minimum Go version a consumer needs. No vulnerability
  in Go 1.27.0 reached this library's code (`govulncheck` found none before the move either). The
  minimum moves with the sibling libraries, which do need Go 1.27.2's security fixes, so a consumer
  has one Go version to meet. Raise your own module's `go` directive to `1.27.2`; from there the go
  command downloads and uses that toolchain by itself.

### Notes

- The gate is green on Go 1.27.2: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  golangci-lint v2.14.0, `go test -race` with **0 races**, and the fuzz target for 30 seconds
  with no failing input. `govulncheck` reports **no vulnerabilities found**.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes
  to `develop`, the pinned GitHub Actions moved to their current commits, the `setup-go` pin
  rolled forward to v7.0.0, `.gitattributes` now pins its own line endings, and CI's linter moved
  to golangci-lint v2.14.0 (the earlier release cannot read Go 1.27.2's compiled standard
  library).

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
