package dcql

// authorityMatches applies OID4VP §6.1.1: the candidate matches when its
// issuer matches at least one value of at least one trusted_authorities
// entry (OR across entries, OR across values). Absent trusted_authorities
// means no constraint. Unknown types never match (Validate() rejects them
// up front — T-05.5: unknown type = query invalid).
func authorityMatches(tas []TrustedAuthority, ref AuthorityRef) bool {
	if len(tas) == 0 {
		return true
	}
	for i := range tas {
		var have []string
		switch tas[i].Type {
		case AuthorityTypeAKI:
			have = ref.AKIs // §6.1.1: base64url KeyIdentifier of an AKI in the chain
		case AuthorityTypeETSITL:
			have = ref.TrustedListURIs // §6.1.1: ETSI TS 119 612 trusted list identifier
		case AuthorityTypeOpenIDFederation:
			have = ref.FederationIDs // §6.1.1: OpenID Federation Entity Identifier
		default:
			continue
		}
		for _, want := range tas[i].Values {
			for _, got := range have {
				if got == want {
					return true
				}
			}
		}
	}
	return false
}
