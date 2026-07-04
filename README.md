# go-dcql

DCQL (Digital Credentials Query Language) for OpenID4VP 1.0 §6/§7 in Go:
model, strict parsing, validation, a pure matcher for verified credentials,
and registered-scope checking against ETSI TS5 intended-use registrations.

- Stdlib only; framework-free; no crypto — matching operates on
  already-verified credentials.
- Formats: `mso_mdoc` and `dc+sd-jwt` (HAIP 1.0 profile).
- `Unmet`/scope explanations carry claim paths, never claim values.

Implemented specs: OpenID4VP 1.0 (final) §6, §7, Annex B.2/B.3 meta
parameters; ETSI TS5 v1.3 §2.4 credential/claim registration mirror.

Status: pre-v1. API frozen no earlier than OIDF conformance pass.
