package types

// signatures.go contains all of the types and functions related to creating
// and verifying transaction signatures. There are a lot of rules surrounding
// the correct use of signatures. Signatures can cover part or all of a
// transaction, can be multiple different algorithms, and must satify a field
// called 'UnlockConditions'.

import (
	"errors"
	"fmt"

	"github.com/rivine/rivine/crypto"
	"golang.org/x/crypto/ed25519"
)

var (
	// These Specifiers enumerate the types of signatures that are recognized
	// by this implementation. If a signature's type is unrecognized, the
	// signature is treated as invalid.
	SignatureEd25519 = Specifier{'e', 'd', '2', '5', '5', '1', '9'}

	ErrMissingTransactionSignature = errors.New("transaction misses a signature")
	ErrInvalidSignatureAlgorithm   = errors.New("invalid signature algorithm")
	ErrInvalidTransactionSignature = errors.New("invalid transaction signature")

	ErrEntropyKey                = errors.New("transaction tries to sign an entproy public key")
	ErrFrivolousSignature        = errors.New("transaction contains a frivolous signature")
	ErrInvalidPubKeyIndex        = errors.New("transaction contains a signature that points to a nonexistent public key")
	ErrInvalidUnlockHashChecksum = errors.New("provided unlock hash has an invalid checksum")
	ErrMissingSignatures         = errors.New("transaction has inputs with missing signatures")
	ErrPrematureSignature        = errors.New("timelock on signature has not expired")
	ErrPublicKeyOveruse          = errors.New("public key was used multiple times while signing transaction")
	ErrSortedUniqueViolation     = errors.New("sorted unique violation")
	ErrUnlockHashWrongLen        = errors.New("marshalled unlock hash is the wrong length")
	ErrWholeTransactionViolation = errors.New("covered fields violation")
)

type (

	// A CryptoPublicKey is a public key prefixed by a Specifier. The Specifier
	// indicates the algorithm used for signing and verification. Unrecognized
	// algorithms will always verify, which allows new algorithms to be added to
	// the protocol via a soft-fork.
	CryptoPublicKey struct {
		Algorithm Specifier `json:"algorithm"`
		Key       []byte    `json:"key"`
	}
)

// Ed25519PublicKey returns pk as a CryptoPublicKey,
// denoting its algorithm as
// Ed25519.
func Ed25519PublicKey(pk crypto.PublicKey) CryptoPublicKey {
	return CryptoPublicKey{
		Algorithm: SignatureEd25519,
		Key:       pk[:],
	}
}

// SignatureAlgorithm defines an algorithm used for creating a signature,
// given a privateKey and input message.
type SignatureAlgorithm interface {
	Sign(privateKey, message []byte) []byte
	Verify(publicKey, message, signature []byte) bool
}

// _RegisteredSignatureAlgorithms contains all registered/known signature algorithms
var _RegisteredSignatureAlgorithms = map[Specifier]SignatureAlgorithm{}

// RegisterSignatureAlgorithm allows you to register a non-nil signature algorithm,
// effectively associating an algorithm to a specifier.
func RegisterSignatureAlgorithm(specifier Specifier, algo SignatureAlgorithm) {
	if algo == nil {
		panic("cannot register nil SignFunc")
	}
	_RegisteredSignatureAlgorithms[specifier] = algo
}

// UnregisterSignatureAlgorithm allows you to unregister a non-nil signature algorithm,
// effectively disassociating an algorithm from a specifier.
func UnregisterSignatureAlgorithm(specifier Specifier) {
	delete(_RegisteredSignatureAlgorithms, specifier)
}

// Ed25519SignatureAlgorithm implements the ed25519 signature algorithm.
type Ed25519SignatureAlgorithm struct{}

// Sign implements SignatureAlgorithm.Sign
func (e Ed25519SignatureAlgorithm) Sign(privateKey, message []byte) []byte {
	if len(privateKey) != ed25519.PrivateKeySize {
		panic("invalid private key size")
	}
	return ed25519.Sign(
		ed25519.PrivateKey(privateKey),
		message)
}

// Verify implements SignatureAlgorithm.Verify
func (e Ed25519SignatureAlgorithm) Verify(publicKey, message, signature []byte) bool {
	if len(publicKey) != ed25519.PublicKeySize {
		panic("invalid public key size")
	}
	return ed25519.Verify(
		ed25519.PublicKey(publicKey),
		message,
		signature)
}

// validSignatures checks the validaty of all signatures in a transaction.
func (t *Transaction) validSignature() error {
	if len(t.Signature) == 0 {
		return ErrMissingTransactionSignature
	}
	algo, found := _RegisteredSignatureAlgorithms[t.PublicKey.Algorithm]
	if !found {
		return ErrInvalidSignatureAlgorithm
	}
	message := crypto.HashAll(
		t.CoinInputs,
		t.CoinOutputs,
		t.BlockStakeInputs,
		t.BlockStakeOutputs,
		t.MinerFees,
		t.ArbitraryData,
		t.PublicKey,
	)
	if !algo.Verify(t.PublicKey.Key, message[:], t.Signature) {
		return ErrInvalidTransactionSignature
	}

	return nil // valid
}

// String defines how to print a SiaPublicKey - hex is used to keep things
// compact during logging. The key type prefix and lack of a checksum help to
// separate it from a sia address.
func (spk *CryptoPublicKey) String() string {
	return spk.Algorithm.String() + ":" + fmt.Sprintf("%x", spk.Key)
}
