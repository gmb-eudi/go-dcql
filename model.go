package dcql

// Credential format identifiers profiled by HAIP 1.0.
const (
	FormatMdoc  = "mso_mdoc"  // OID4VP Annex B.2
	FormatSDJWT = "dc+sd-jwt" // OID4VP Annex B.3
)

// Trusted-authority query types ([OID4VP §6.1.1]).
const (
	AuthorityTypeAKI              = "aki"
	AuthorityTypeETSITL           = "etsi_tl"
	AuthorityTypeOpenIDFederation = "openid_federation"
)

// Query is a DCQL query — faithful [OID4VP §6] model, json tags exact.
type Query struct {
	Credentials    []CredentialQuery    `json:"credentials"`
	CredentialSets []CredentialSetQuery `json:"credential_sets,omitempty"`
}

// CredentialQuery per [OID4VP §6.1].
type CredentialQuery struct {
	ID                                string             `json:"id"`
	Format                            string             `json:"format"`
	Multiple                          bool               `json:"multiple,omitempty"` // [OID4VP §6.1]: default false
	Meta                              *Meta              `json:"meta,omitempty"`     // [OID4VP §6.1]: REQUIRED — enforced by Validate
	TrustedAuthorities                []TrustedAuthority `json:"trusted_authorities,omitempty"`
	RequireCryptographicHolderBinding *bool              `json:"require_cryptographic_holder_binding,omitempty"` // [OID4VP §6.1]: default true
	Claims                            []ClaimsQuery      `json:"claims,omitempty"`
	ClaimSets                         [][]string         `json:"claim_sets,omitempty"`
}

// HolderBindingRequired resolves the [OID4VP §6.1] default (true).
func (c *CredentialQuery) HolderBindingRequired() bool {
	return c.RequireCryptographicHolderBinding == nil || *c.RequireCryptographicHolderBinding
}

// Meta carries the format-specific parameters (OID4VP Annex B.2.3 / B.3.5).
// Exactly one side is populated, matching Format — enforced by Validate.
type Meta struct {
	VCTValues    []string `json:"vct_values,omitempty"`    // dc+sd-jwt
	DoctypeValue string   `json:"doctype_value,omitempty"` // mso_mdoc
}

// ClaimsQuery per [OID4VP §6.3].
type ClaimsQuery struct {
	ID     string    `json:"id,omitempty"` // required when claim_sets present ([OID4VP §6.3])
	Path   ClaimPath `json:"path"`
	Values []any     `json:"values,omitempty"` // strings, integers, booleans ([OID4VP §6.3])
}

// CredentialSetQuery per [OID4VP §6.2].
type CredentialSetQuery struct {
	Options  [][]string `json:"options"`
	Required *bool      `json:"required,omitempty"` // [OID4VP §6.2]: default true
}

// IsRequired resolves the [OID4VP §6.2] default (true).
func (s *CredentialSetQuery) IsRequired() bool { return s.Required == nil || *s.Required }

// TrustedAuthority per [OID4VP §6.1.1].
type TrustedAuthority struct {
	Type   string   `json:"type"`
	Values []string `json:"values"`
}
