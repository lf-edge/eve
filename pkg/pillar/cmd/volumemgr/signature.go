package volumemgr

// SignatureVerifier an expected signature, the public key used to verify it
// and the chain expected to sign the public key.
// Can be used to verify the signature of some bytes.
type SignatureVerifier struct {
	Signature        []byte   //signature of image
	PublicKey        string   //certificate containing public key
	CertificateChain []string //name of intermediate certificates
}
