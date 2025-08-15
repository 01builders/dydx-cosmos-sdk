package secp256k1

import (
	"github.com/cometbft/cometbft/crypto"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	ecdaKey, err := ethcrypto.ToECDSA(privKey.Key)
	if err != nil {
		return nil, err
	}
	rsv, err := ethcrypto.Sign(crypto.Sha256(msg), ecdaKey)
	if err != nil {
		return nil, err
	}
	// we do not need v  in r||s||v:
	rs := rsv[:len(rsv)-1]
	return rs, nil
}

// VerifySignature validates the signature.
// The msg will be hashed prior to signature verification.
func (pubKey *PubKey) VerifySignature(msg, sigStr []byte) bool {
	return ethcrypto.VerifySignature(pubKey.Bytes(), crypto.Sha256(msg), sigStr)
}
