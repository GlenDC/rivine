package types

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

type (
	UnlockCondition interface {
		UnlockType() UnlockType
		UnlockHash() UnlockHash // is it just here for legac reasons or does it still serve a purpose?
		IsStandardCondition() error
	}

	UnlockFulfillment interface {
		Fulfill(condition interface{}, ctx FulfillContext) error
		UnlockType() UnlockType
		IsStandardFulfillment() error
	}

	UnlockConstructorPair struct {
		ConditionConstructor   func() UnlockCondition
		FulfillmentConstructor func() UnlockFulfillment
	}

	FulfillContext struct {
		InputIndex  uint64
		Transaction Transaction
	}
)

var (
	ErrUnexpectedUnlockCondition = errors.New("unexpected unlock condition")
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

	// SingleSignatureCondition (0x01) is the only and most simplest unlocker.
	// It uses a public key (used as UnlockHash), such that only one public key is expected.
	// The spender will need to proof ownership of that public key by providing a correct signature.
	SingleSignatureCondition struct {
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
	// AtomicSwapSecret defines the 256 pre-image byte slice,
	// used as secret within the Atomic Swap protocol/contract.
	AtomicSwapSecret [sha256.Size]byte
	// AtomicSwapHashedSecret defines the 256 image byte slice,
	// used as hashed secret within the Atomic Swap protocol/contract.
	AtomicSwapHashedSecret [sha256.Size]byte

	LegacyCondition struct {
		TargetUnlockHash UnlockHash
	}
	LegacyFulfillment struct {
		Condition   UnlockCondition
		Fulfillment UnlockFulfillment
	}

	TimeLockCondition struct {
		TimeLock Timestamp `json:"timelock"`
	}
	TimeLockFulfillment struct{}

	SortedConditionSet struct {
		Conditions []UnlockCondition `json:"conditions"`
	}
	SortedFulfillmentSet struct {
		Fulfillments []UnlockFulfillment `json:"fulfillments"`
	}
)

func (n NilCondition) UnlockType() UnlockType     { return UnlockTypeNil }
func (n NilCondition) UnlockHash() UnlockHash     { return UnlockHash{} }
func (n NilCondition) IsStandardCondition() error { return nil } // always valid

func (n NilFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (n NilFulfillment) UnlockType() UnlockType                    { return UnlockTypeNil }
func (n NilFulfillment) IsStandardFulfillment() error              { return nil } // always valid

func (u UnknownCondition) UnlockType() UnlockType { return u.Type }
func (u UnknownCondition) UnlockHash() UnlockHash {
	return NewUnlockHash(u.Type, crypto.HashObject(u.RawCondition))
}
func (u UnknownCondition) IsStandardCondition() error { return ErrUnknownUnlockType } // never valid

func (u UnknownFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (u UnknownFulfillment) UnlockType() UnlockType                    { return u.Type }
func (u UnknownFulfillment) IsStandardFulfillment() error              { return ErrUnknownUnlockType } // never valid

func (ss SingleSignatureCondition) UnlockType() UnlockType { return UnlockTypeSingleSignature }
func (ss SingleSignatureCondition) UnlockHash() UnlockHash { return ss.TargetUnlockHash }
func (ss SingleSignatureCondition) IsStandardCondition() error {
	if ss.TargetUnlockHash.Type != UnlockTypeSingleSignature {
		return errors.New("unsupported unlock hash type")
	}
	if ss.TargetUnlockHash.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	return nil
}

func (ss SingleSignatureFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case SingleSignatureCondition:
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
func (as AtomicSwapFulfillment) UnlockType() UnlockType { return UnlockTypeSingleSignature }
func (as AtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (tl TimeLockCondition) UnlockType() UnlockType { return UnlockTypeTimeLock }
func (tl TimeLockCondition) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeTimeLock, crypto.HashObject(tl.TimeLock))
}
func (tl TimeLockCondition) IsStandardCondition() error { return nil } // TODO: should we validate time somehow?

func (tl TimeLockFulfillment) Fulfill(condition interface{}, _ FulfillContext) error {
	switch tc := condition.(type) {
	case TimeLockCondition:
		if CurrentTimestamp() < tc.TimeLock {
			return errors.New("condition is still time locked")
		}
		return nil
	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (tl TimeLockFulfillment) UnlockType() UnlockType       { return UnlockTypeTimeLock }
func (tl TimeLockFulfillment) IsStandardFulfillment() error { return nil } // TODO: should we validate time somehow?

func (ss SortedConditionSet) UnlockType() UnlockType { return UnlockTypeSortedSet }
func (ss SortedConditionSet) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeSortedSet, crypto.HashObject(ss.Conditions))
}
func (ss SortedConditionSet) IsStandardCondition() error {
	n := len(ss.Conditions)
	if n == 0 {
		return errors.New("sorted condition set cannot be empty")
	}
	var (
		err    error
		exists bool
		cts    = make(map[UnlockType]struct{}, n)
	)
	for _, condition := range ss.Conditions {
		err = condition.IsStandardCondition()
		if err != nil {
			return err
		}
		ct := condition.UnlockType()
		if ct == UnlockTypeSortedSet {
			return errors.New("sorted condition sets cannot be nested")
		}
		if _, exists = cts[ct]; exists {
			return errors.New("all conditions in a sorted set have to be unique")
		}
		cts[ct] = struct{}{}
	}
	return nil
}

func (ss SortedFulfillmentSet) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case SortedConditionSet:
		fn := len(ss.Fulfillments)
		cn := len(tc.Conditions)
		if fn != cn {
			return errors.New("sorted sets have non matching unlock part length")
		}
		if fn == 0 {
			return errors.New("sorted set contains no conditions")
		}
		var err error
		for idx, fulfillment := range ss.Fulfillments {
			err = fulfillment.Fulfill(tc.Conditions[idx], ctx)
			if err != nil {
				return err
			}
		}
		return nil
	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (ss SortedFulfillmentSet) UnlockType() UnlockType { return UnlockTypeSortedSet }
func (ss SortedFulfillmentSet) IsStandardFulfillment() error {
	n := len(ss.Fulfillments)
	if n == 0 {
		return errors.New("sorted fulfillment set cannot be empty")
	}
	var (
		err    error
		exists bool
		fts    = make(map[UnlockType]struct{}, n)
	)
	for _, fulfillment := range ss.Fulfillments {
		err = fulfillment.IsStandardFulfillment()
		if err != nil {
			return err
		}
		ft := fulfillment.UnlockType()
		if ft == UnlockTypeSortedSet {
			return errors.New("sorted fulfillment sets cannot be nested")
		}
		if _, exists = fts[ft]; exists {
			return errors.New("all fulfillments in a sorted set have to be unique")
		}
		fts[ft] = struct{}{}
	}
	return nil
}

func (l LegacyCondition) UnlockType() UnlockType { return l.TargetUnlockHash.Type }
func (l LegacyCondition) UnlockHash() UnlockHash { return l.TargetUnlockHash }
func (l LegacyCondition) IsStandardCondition() error {
	switch l.TargetUnlockHash.Type {
	case UnlockTypeSingleSignature, UnlockTypeAtomicSwap:
		if l.TargetUnlockHash.Hash == (crypto.Hash{}) {
			return errors.New("nil crypto hash cannot be used as unlock hash")
		}
		return nil
	default:
		return errors.New("given unlock hash's unlock type wasn't standard at the time of legacy")
	}
}

func (l LegacyFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case LegacyCondition:
		uh := l.Condition.UnlockHash()
		if uh.Cmp(tc.TargetUnlockHash) != 0 {
			return errors.New("unknown/wrong unlock hasH")
		}
		return l.Fulfillment.Fulfill(l.Condition, ctx)
	default:
		return ErrUnexpectedUnlockCondition
	}
}
func (l LegacyFulfillment) UnlockType() UnlockType { return UnlockTypeSingleSignature }
func (l LegacyFulfillment) IsStandardFulfillment() error {
	if l.Condition == nil {
		return errors.New("no condition given")
	}
	if l.Fulfillment == nil {
		return errors.New("no fulfillment given")
	}
	err := l.Condition.IsStandardCondition()
	if err != nil {
		return err
	}
	return l.Fulfillment.IsStandardFulfillment()
}

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
