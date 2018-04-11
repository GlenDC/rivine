package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

// TODO: ensure we can fulfill legacy conditions

type (
	UnlockCondition interface {
		UnlockType() UnlockType
		UnlockHash() UnlockHash // is it just here for legacy reasons or does it still serve a purpose?
		IsStandardCondition() error

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockFulfillment interface {
		Fulfill(condition interface{}, ctx FulfillContext) error
		UnlockType() UnlockType
		IsStandardFulfillment() error

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockConstructorPair struct {
		ConditionConstructor   func() UnlockCondition
		FulfillmentConstructor func() UnlockFulfillment
	}

	FulfillContext struct {
		InputIndex  uint64
		BlockHeight BlockHeight
		Transaction Transaction
	}
)

const (
	// AtomicSwapSecretLen is the required/fixed length
	// of an atomic swap secret, the pre-image of an hashed secret.
	AtomicSwapSecretLen = sha256.Size
	// AtomicSwapHashedSecretLen is the required/fixed length
	// of an atomic swap hashed secret, the post-image of a secret.
	AtomicSwapHashedSecretLen = sha256.Size
)

var (
	ErrUnexpectedUnlockCondition = errors.New("unexpected unlock condition")

	// ErrUnknownUnlockType is an error returned in case
	// one tries to use an input lock of unknown type where it's not supported
	ErrUnknownUnlockType = errors.New("unknown unlock type")

	// ErrUnknownSignAlgorithmType is an error returned in case
	// one tries to sign using an unknown signing algorithm type.
	//
	// NOTE That verification of unknown signing algorithm types does always succeed!
	ErrUnknownSignAlgorithmType = errors.New("unknown signature algorithm type")
)

func RegisterUnlockConstructorPair(ut UnlockType, cp UnlockConstructorPair) {
	ccNotGiven, fcNotGiven := cp.ConditionConstructor == nil, cp.FulfillmentConstructor == nil
	if ccNotGiven && fcNotGiven {
		delete(_RegisteredUnlockConsturctorPairs, ut)
	}
	if ccNotGiven {
		panic("condition constructor has to be given if fulfillment constructor is given")
	}
	if fcNotGiven {
		panic("fulfillment constructor has to be given if condition constructor is given")
	}
	_RegisteredUnlockConsturctorPairs[ut] = cp
}

var (
	_RegisteredUnlockConsturctorPairs = map[UnlockType]UnlockConstructorPair{}
)

type (
	NilCondition   struct{}
	NilFulfillment struct{}

	UnknownCondition struct {
		Type         UnlockType
		RawCondition []byte
	}
	UnknownFulfillment struct {
		Type           UnlockType
		RawFulfillment []byte
	}

	UnlockHashCondition struct {
		TargetUnlockHash UnlockHash `json:"unlockhash"`
	}
	SingleSignatureFulfillment struct {
		PublicKey SiaPublicKey `json:"publickey"`
		Signature ByteSlice    `json:"signature"`
	}

	// AtomicSwapCondition defines the condition of an atomic swap contract/input-lock.
	AtomicSwapCondition struct {
		Sender       UnlockHash             `json:"sender"`
		Receiver     UnlockHash             `json:"receiver"`
		HashedSecret AtomicSwapHashedSecret `json:"hashedsecret"`
		TimeLock     Timestamp              `json:"timelock"`
	}
	// AtomicSwapFulfillment defines the fulfillment of an atomic swap contract/input-lock.
	AtomicSwapFulfillment struct {
		PublicKey SiaPublicKey     `json:"publickey"`
		Signature ByteSlice        `json:"signature"`
		Secret    AtomicSwapSecret `json:"secret"`
	}
	LegacyAtomicSwapFulfillment struct { // legacy fulfillment as used in transactions of version 0
		Sender       UnlockHash
		Receiver     UnlockHash
		HashedSecret AtomicSwapHashedSecret
		TimeLock     Timestamp
		PublicKey    SiaPublicKey
		Signature    ByteSlice
		Secret       AtomicSwapSecret
	}
	// AtomicSwapSecret defines the 256 pre-image byte slice,
	// used as secret within the Atomic Swap protocol/contract.
	AtomicSwapSecret [sha256.Size]byte
	// AtomicSwapHashedSecret defines the 256 image byte slice,
	// used as hashed secret within the Atomic Swap protocol/contract.
	AtomicSwapHashedSecret [sha256.Size]byte
)

func (n NilCondition) UnlockType() UnlockType     { return UnlockTypeNil }
func (n NilCondition) UnlockHash() UnlockHash     { return UnlockHash{} }
func (n NilCondition) IsStandardCondition() error { return nil } // always valid

func (n NilCondition) Marshal() []byte          { return nil } // nothing to marshal
func (n NilCondition) Unmarshal(b []byte) error { return nil } // nothing to unmarshal

func (n NilFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (n NilFulfillment) UnlockType() UnlockType                    { return UnlockTypeNil }
func (n NilFulfillment) IsStandardFulfillment() error              { return nil } // always valid

func (n NilFulfillment) Marshal() []byte          { return nil } // nothing to marshal
func (n NilFulfillment) Unmarshal(b []byte) error { return nil } // nothing to unmarshal

func (u UnknownCondition) UnlockType() UnlockType { return u.Type }
func (u UnknownCondition) UnlockHash() UnlockHash {
	return NewUnlockHash(u.Type, crypto.HashObject(u.RawCondition))
}
func (u UnknownCondition) IsStandardCondition() error { return ErrUnknownUnlockType } // never valid

func (u UnknownCondition) Marshal() []byte {
	return u.RawCondition
}
func (u UnknownCondition) Unmarshal(b []byte) error {
	if len(b) == 0 {
		return errors.New("no bytes given to unmarsal into a raw condition")
	}
	u.RawCondition = b
	return nil
}

func (u UnknownFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (u UnknownFulfillment) UnlockType() UnlockType                    { return u.Type }
func (u UnknownFulfillment) IsStandardFulfillment() error              { return ErrUnknownUnlockType } // never valid

func (u UnknownFulfillment) Marshal() []byte {
	return u.RawFulfillment
}
func (u UnknownFulfillment) Unmarshal(b []byte) error {
	if len(b) == 0 {
		return errors.New("no bytes given to unmarsal into a raw fulfillment")
	}
	u.RawFulfillment = b
	return nil
}

func (uh UnlockHashCondition) UnlockType() UnlockType { return uh.TargetUnlockHash.Type }
func (uh UnlockHashCondition) UnlockHash() UnlockHash { return uh.TargetUnlockHash }
func (uh UnlockHashCondition) IsStandardCondition() error {
	if uh.TargetUnlockHash.Type != UnlockTypeSingleSignature && uh.TargetUnlockHash.Type != UnlockTypeAtomicSwap {
		return errors.New("unsupported unlock type by unlock hash condition")
	}
	if uh.TargetUnlockHash.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	return nil
}

func (uh UnlockHashCondition) Marshal() []byte {
	return encoding.Marshal(uh.TargetUnlockHash)
}
func (uh UnlockHashCondition) Unmarshal(b []byte) error {
	return encoding.Unmarshal(b, &uh.TargetUnlockHash)
}

func NewSingleSignatureFulfillment() (SingleSignatureFulfillment, error) {
	panic("TODO")
}

func (ss SingleSignatureFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case UnlockHashCondition:
		uh := NewUnlockHash(UnlockTypeSingleSignature,
			crypto.HashObject(encoding.Marshal(ss.PublicKey)))
		if uh != tc.TargetUnlockHash {
			return errors.New("fulfillment provides wrong public key")
		}
		return verifyHashUsingSiaPublicKey(ss.PublicKey,
			ctx.InputIndex, ctx.Transaction, ss.Signature)

	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (ss SingleSignatureFulfillment) UnlockType() UnlockType { return UnlockTypeSingleSignature }
func (ss SingleSignatureFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(ss.PublicKey, ss.Signature)
}

func (ss SingleSignatureFulfillment) Marshal() []byte {
	return encoding.MarshalAll(ss.PublicKey, ss.Signature)
}
func (ss SingleSignatureFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &ss.PublicKey, &ss.Signature)
}

func (as AtomicSwapCondition) UnlockType() UnlockType { return UnlockTypeAtomicSwap }
func (as AtomicSwapCondition) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeAtomicSwap, crypto.HashObject(encoding.Marshal(as)))
}
func (as AtomicSwapCondition) IsStandardCondition() error {
	if as.Sender.Type != UnlockTypeSingleSignature || as.Receiver.Type != UnlockTypeSingleSignature {
		return errors.New("unsupported unlock hash type")
	}
	if as.Sender.Hash == (crypto.Hash{}) || as.Receiver.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	if as.HashedSecret == (AtomicSwapHashedSecret{}) {
		return errors.New("nil hashed secret not allowed")
	}
	return nil
}

func (as AtomicSwapCondition) Marshal() []byte {
	return encoding.MarshalAll(as.Sender, as.Receiver, as.HashedSecret, as.TimeLock)
}
func (as AtomicSwapCondition) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.Sender, &as.Receiver, &as.HashedSecret, &as.TimeLock)
}

func NewAtomicSwapClaimFulfillment() (AtomicSwapFulfillment, error) {
	panic("TODO")
}

func NewAtomicSwapRefundFulfillment() (AtomicSwapFulfillment, error) {
	panic("TODO")
}

func (as AtomicSwapFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case AtomicSwapCondition:
		// create the unlockHash for the given public Key
		unlockHash := NewSingleSignatureInputLock(as.PublicKey).UnlockHash()

		// prior to our timelock, only the receiver can claim the unspend output
		if CurrentTimestamp() <= tc.TimeLock {
			// verify that receiver public key was given
			if unlockHash.Cmp(tc.Receiver) != 0 {
				return ErrInvalidRedeemer
			}

			// verify signature
			err := verifyHashUsingSiaPublicKey(as.PublicKey,
				ctx.InputIndex, ctx.Transaction, as.Signature, as.PublicKey, as.Secret)
			if err != nil {
				return err
			}

			// in order for the receiver to spend,
			// the secret has to be known
			hashedSecret := NewAtomicSwapHashedSecret(as.Secret)
			if bytes.Compare(tc.HashedSecret[:], hashedSecret[:]) != 0 {
				return ErrInvalidPreImageSha256
			}

			return nil
		}

		// verify that sender public key was given
		if unlockHash.Cmp(tc.Sender) != 0 {
			return ErrInvalidRedeemer
		}

		// after the deadline (timelock),
		// only the original sender can reclaim the unspend output
		return verifyHashUsingSiaPublicKey(as.PublicKey,
			ctx.InputIndex, ctx.Transaction, as.Signature, as.PublicKey)

	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (as AtomicSwapFulfillment) UnlockType() UnlockType { return UnlockTypeAtomicSwap }
func (as AtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as AtomicSwapFulfillment) Marshal() []byte {
	return encoding.MarshalAll(as.PublicKey, as.Signature, as.Secret)
}
func (as AtomicSwapFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.PublicKey, &as.Signature, &as.Secret)
}

func (as LegacyAtomicSwapFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case UnlockHashCondition:
		// ensure the condition equals the ours
		ourHS := AtomicSwapCondition{
			Sender:       as.Sender,
			Receiver:     as.Receiver,
			HashedSecret: as.HashedSecret,
			TimeLock:     as.TimeLock,
		}.UnlockHash()
		if ourHS.Cmp(tc.TargetUnlockHash) != 0 {
			return errors.New("produced unlock hash doesn't equal the expected unlock hash")
		}

		// create the unlockHash for the given public Key
		unlockHash := NewSingleSignatureInputLock(as.PublicKey).UnlockHash()

		// prior to our timelock, only the receiver can claim the unspend output
		if CurrentTimestamp() <= as.TimeLock {
			// verify that receiver public key was given
			if unlockHash.Cmp(as.Receiver) != 0 {
				return ErrInvalidRedeemer
			}

			// verify signature
			err := verifyHashUsingSiaPublicKey(as.PublicKey,
				ctx.InputIndex, ctx.Transaction, as.Signature, as.PublicKey, as.Secret)
			if err != nil {
				return err
			}

			// in order for the receiver to spend,
			// the secret has to be known
			hashedSecret := NewAtomicSwapHashedSecret(as.Secret)
			if bytes.Compare(as.HashedSecret[:], hashedSecret[:]) != 0 {
				return ErrInvalidPreImageSha256
			}

			return nil
		}

		// verify that sender public key was given
		if unlockHash.Cmp(as.Sender) != 0 {
			return ErrInvalidRedeemer
		}

		// after the deadline (timelock),
		// only the original sender can reclaim the unspend output
		return verifyHashUsingSiaPublicKey(as.PublicKey,
			ctx.InputIndex, ctx.Transaction, as.Signature, as.PublicKey)

	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (as LegacyAtomicSwapFulfillment) UnlockType() UnlockType { return UnlockTypeAtomicSwap }
func (as LegacyAtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as LegacyAtomicSwapFulfillment) Marshal() []byte {
	return nil // not supported in legacy fulfillment
}
func (as LegacyAtomicSwapFulfillment) Unmarshal(b []byte) error {
	return errors.New("unmarshal feature not supported in legacy fulfillment")
}

var (
	_ UnlockCondition = NilCondition{}
	_ UnlockCondition = UnknownCondition{}
	_ UnlockCondition = UnlockHashCondition{}
	_ UnlockCondition = AtomicSwapCondition{}

	_ UnlockFulfillment = NilFulfillment{}
	_ UnlockFulfillment = UnknownFulfillment{}
	_ UnlockFulfillment = SingleSignatureFulfillment{}
	_ UnlockFulfillment = AtomicSwapFulfillment{}
	_ UnlockFulfillment = LegacyAtomicSwapFulfillment{}
)

func strictSignatureCheck(pk SiaPublicKey, signature ByteSlice) error {
	switch pk.Algorithm {
	case SignatureEntropy:
		return nil
	case SignatureEd25519:
		if len(pk.Key) != crypto.PublicKeySize {
			return errors.New("invalid public key size in transaction")
		}
		if len(signature) != crypto.SignatureSize {
			return errors.New("invalid signature size in transaction")
		}
		return nil
	default:
		return errors.New("unrecognized public key type in transaction")
	}
}

// TODO: can be removed?
func signHashUsingSiaPublicKey(pk SiaPublicKey, inputIndex uint64, tx Transaction, key interface{}, extraObjects ...interface{}) ([]byte, error) {
	switch pk.Algorithm {
	case SignatureEntropy:
		// Entropy cannot ever be used to sign a transaction.
		return nil, ErrEntropyKey

	case SignatureEd25519:
		// decode the ed-secretKey
		var edSK crypto.SecretKey
		switch k := key.(type) {
		case crypto.SecretKey:
			edSK = k
		case ByteSlice:
			if len(k) != crypto.SecretKeySize {
				return nil, errors.New("invalid secret key size")
			}
			copy(edSK[:], k)
		case []byte:
			if len(k) != crypto.SecretKeySize {
				return nil, errors.New("invalid secret key size")
			}
			copy(edSK[:], k)
		default:
			return nil, fmt.Errorf("%T is an unknown secret key size", key)
		}
		sigHash := tx.InputSigHash(inputIndex, extraObjects...)
		sig := crypto.SignHash(sigHash, edSK)
		return sig[:], nil

	default:
		return nil, ErrUnknownSignAlgorithmType
	}
}

func verifyHashUsingSiaPublicKey(pk SiaPublicKey, inputIndex uint64, tx Transaction, sig []byte, extraObjects ...interface{}) (err error) {
	switch pk.Algorithm {
	case SignatureEntropy:
		// Entropy cannot ever be used to sign a transaction.
		err = ErrEntropyKey

	case SignatureEd25519:
		// Decode the public key and signature.
		var (
			edPK  crypto.PublicKey
			edSig crypto.Signature
		)
		copy(edPK[:], pk.Key)
		copy(edSig[:], sig)
		cryptoSig := crypto.Signature(edSig)
		sigHash := tx.InputSigHash(inputIndex, extraObjects...)
		err = crypto.VerifyHash(sigHash, edPK, cryptoSig)

	default:
		// If the identifier is not recognized, assume that the signature
		// is valid. This allows more signature types to be added via soft
		// forking.
	}

	return
}
