package user

import "crypto/rsa"

// CryptoSuite is product of a successful login.
//
// It contains both the users public and private key,
// the later of which can be used to decrypt document-specific keys.
// Please note that the public key IS NOT encrypted here,
// and as such MUST NOT be persisted outside of memory.
type CryptoSuite struct {
	PublicKey  *rsa.PublicKey
	PrivateKey *rsa.PrivateKey
}
