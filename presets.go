package dcql

// Preset queries for common EUDI use cases (T-05.7). Identifiers per ARF
// 2.9: mdoc PID doctype/namespace eu.europa.ec.eudi.pid.1 (ARF Topic 3 HLRs),
// SD-JWT VC PID vct urn:eudi:pid:1 (PID_14), mDL doctype
// org.iso.18013.5.1.mDL / namespace org.iso.18013.5.1 (ISO 18013-5).

// PresetPIDAgeOver18 requests proof of being over 18 from a PID, accepting
// the mdoc or the SD-JWT VC encoding via one required credential_set with
// two options (OID4VP §6.2).
//
// Withdrawal caveat: the upstream PID Rulebook (eudi-doc-attestation-rulebooks-
// catalog, rulebooks/pid/pid-rulebook.md, current as of 2026-07-03) removed
// age_over_18 (and all age-verification attributes) from the PID attribute
// catalog in v1.1 (4 Sep 2025) "following CIR 2024/2977"; the current
// version (v1.6, 1 Jul 2026) and the CIR (EU) 2024/2977 Annex itself list
// no age attribute at all. PresetPIDAgeOver18 is kept using age_over_18 per
// this task's brief — no replacement identifier exists in the current PID
// schema to substitute — but callers should treat it as targeting a
// deprecated/withdrawn attribute pending a dedicated Age Verification
// attestation rulebook upstream. See SOURCE.md for exact citations.
func PresetPIDAgeOver18() *Query {
	return &Query{
		Credentials: []CredentialQuery{
			{
				ID:     "pid_mdoc",
				Format: FormatMdoc,
				Meta:   &Meta{DoctypeValue: "eu.europa.ec.eudi.pid.1"},
				Claims: []ClaimsQuery{{
					Path:   NewPath(Key("eu.europa.ec.eudi.pid.1"), Key("age_over_18")),
					Values: []any{true},
				}},
			},
			{
				ID:     "pid_sdjwt",
				Format: FormatSDJWT,
				Meta:   &Meta{VCTValues: []string{"urn:eudi:pid:1"}},
				Claims: []ClaimsQuery{{
					Path:   NewPath(Key("age_over_18")),
					Values: []any{true},
				}},
			},
		},
		CredentialSets: []CredentialSetQuery{
			{Options: [][]string{{"pid_mdoc"}, {"pid_sdjwt"}}},
		},
	}
}

// PresetPIDFull requests a PID with its mandatory-to-present claims: the
// claims member is deliberately absent (OID4VP §6.4.1 — the wallet returns
// the claims mandatory to present), so no claim names are hardcoded here.
func PresetPIDFull() *Query {
	return &Query{
		Credentials: []CredentialQuery{
			{
				ID:     "pid_mdoc",
				Format: FormatMdoc,
				Meta:   &Meta{DoctypeValue: "eu.europa.ec.eudi.pid.1"},
			},
			{
				ID:     "pid_sdjwt",
				Format: FormatSDJWT,
				Meta:   &Meta{VCTValues: []string{"urn:eudi:pid:1"}},
			},
		},
		CredentialSets: []CredentialSetQuery{
			{Options: [][]string{{"pid_mdoc"}, {"pid_sdjwt"}}},
		},
	}
}

// PresetMDLDrivingPrivileges requests the driving_privileges element of an
// ISO/IEC 18013-5 mobile driving licence.
func PresetMDLDrivingPrivileges() *Query {
	return &Query{
		Credentials: []CredentialQuery{
			{
				ID:     "mdl",
				Format: FormatMdoc,
				Meta:   &Meta{DoctypeValue: "org.iso.18013.5.1.mDL"},
				Claims: []ClaimsQuery{{
					Path: NewPath(Key("org.iso.18013.5.1"), Key("driving_privileges")),
				}},
			},
		},
	}
}
