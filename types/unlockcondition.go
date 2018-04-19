package types

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rivine/rivine/build"
	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

type (
	UnlockCondition interface {
		ConditionType() ConditionType
		IsStandardCondition() error

		// TODO: check if we really need this function, internally
		UnlockHash() UnlockHash

		Equal(UnlockCondition) bool
	}
	MarshalableUnlockCondition interface {
		UnlockCondition

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockFulfillment interface {
		Fulfill(condition UnlockCondition, ctx FulfillContext) error
		Sign(ctx FulfillmentSignContext) error

		// TODO: check if we really need this function, internally
		UnlockHash() UnlockHash

		Equal(UnlockFulfillment) bool

		FulfillmentType() FulfillmentType
		IsStandardFulfillment() error
	}
	MarshalableUnlockFulfillment interface {
		UnlockFulfillment

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockConditionProxy struct {
		Condition MarshalableUnlockCondition
	}
	UnlockFulfillmentProxy struct {
		Fulfillment MarshalableUnlockFulfillment
	}

	FulfillmentSignContext struct {
		InputIndex  uint64
		Transaction Transaction
		Key         interface{}
	}

	FulfillContext struct {
		InputIndex  uint64
		BlockHeight BlockHeight
		Transaction Transaction
	}

	ConditionType   byte
	FulfillmentType byte
)

const (
	ConditionTypeNil ConditionType = iota
	ConditionTypeUnlockHash
	ConditionTypeAtomicSwap
)

const (
	FulfillmentTypeNil FulfillmentType = iota
	FulfillmentTypeSingleSignature
	FulfillmentTypeAtomicSwap
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

	ErrFulfillmentDoubleSign = errors.New("cannot sign a fulfillment which is already signed")

	// ErrUnknownUnlockType is an error returned in case
	// one tries to use an input lock of unknown type where it's not supported
	ErrUnknownUnlockType = errors.New("unknown unlock type")

	ErrUnknownConditionType   = errors.New("unknown condition type")
	ErrUnknownFulfillmentType = errors.New("unknown fulfillment type")

	ErrNilFulfillmentType = errors.New("nil fulfillment type")

	// ErrUnknownSignAlgorithmType is an error returned in case
	// one tries to sign using an unknown signing algorithm type.
	//
	// NOTE That verification of unknown signing algorithm types does always succeed!
	ErrUnknownSignAlgorithmType = errors.New("unknown signature algorithm type")
)

func RegisterUnlockConditionType(ct ConditionType, cc MarshalableUnlockConditionConstructor) {
	if cc == nil {
		delete(_RegisteredUnlockConditionTypes, ct)
	}
	_RegisteredUnlockConditionTypes[ct] = cc
}

func RegisterUnlockFulfillmentType(ft FulfillmentType, fc MarshalableUnlockFulfillmentConstructor) {
	if fc == nil {
		delete(_RegisteredUnlockFulfillmentTypes, ft)
	}
	_RegisteredUnlockFulfillmentTypes[ft] = fc
}

type (
	MarshalableUnlockConditionConstructor   func() MarshalableUnlockCondition
	MarshalableUnlockFulfillmentConstructor func() MarshalableUnlockFulfillment
)

var (
	_RegisteredUnlockConditionTypes = map[ConditionType]MarshalableUnlockConditionConstructor{
		ConditionTypeNil:        func() MarshalableUnlockCondition { return &NilCondition{} },
		ConditionTypeUnlockHash: func() MarshalableUnlockCondition { return &UnlockHashCondition{} },
		ConditionTypeAtomicSwap: func() MarshalableUnlockCondition { return &AtomicSwapCondition{} },
	}
	_RegisteredUnlockFulfillmentTypes = map[FulfillmentType]MarshalableUnlockFulfillmentConstructor{
		FulfillmentTypeNil:             func() MarshalableUnlockFulfillment { return &NilFulfillment{} },
		FulfillmentTypeSingleSignature: func() MarshalableUnlockFulfillment { return &SingleSignatureFulfillment{} },
		FulfillmentTypeAtomicSwap:      func() MarshalableUnlockFulfillment { return &anyAtomicSwapFulfillment{} },
	}
)

type (
	NilCondition   struct{} // can only be fulfilled by a SingleSignatureFulfillment
	NilFulfillment struct{} // invalid fulfillment

	UnknownCondition struct {
		Type         ConditionType
		RawCondition []byte
	}
	UnknownFulfillment struct {
		Type           FulfillmentType
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
		Secret    AtomicSwapSecret `json:"secret,omitempty"`
	}
	LegacyAtomicSwapFulfillment struct { // legacy fulfillment as used in transactions of version 0
		Sender       UnlockHash             `json:"sender"`
		Receiver     UnlockHash             `json:"receiver"`
		HashedSecret AtomicSwapHashedSecret `json:"hashedsecret"`
		TimeLock     Timestamp              `json:"timelock"`
		PublicKey    SiaPublicKey           `json:"publickey"`
		Signature    ByteSlice              `json:"signature"`
		Secret       AtomicSwapSecret       `json:"secret,omitempty"`
	}
	// AtomicSwapSecret defines the 256 pre-image byte slice,
	// used as secret within the Atomic Swap protocol/contract.
	AtomicSwapSecret [sha256.Size]byte
	// AtomicSwapHashedSecret defines the 256 image byte slice,
	// used as hashed secret within the Atomic Swap protocol/contract.
	AtomicSwapHashedSecret [sha256.Size]byte
)

type (
	// anyAtomicSwapFulfillment is used to be able to unmarshal an atomic swap fulfillment,
	// no matter if it's in the legacy format or in the original format.
	anyAtomicSwapFulfillment struct {
		MarshalableUnlockFulfillment
	}
)

// Errors related to atomic swaps
var (
	ErrInvalidPreImageSha256 = errors.New("invalid pre-image sha256")
	ErrInvalidRedeemer       = errors.New("invalid input redeemer")
)

func (n *NilCondition) ConditionType() ConditionType { return ConditionTypeNil }
func (n *NilCondition) IsStandardCondition() error   { return nil } // always valid

func (n *NilCondition) UnlockHash() UnlockHash { return NilUnlockHash }

func (n *NilCondition) Equal(c UnlockCondition) bool {
	if c == nil {
		return true // implicit equality
	}
	_, equal := c.(*NilCondition)
	return equal // explicit equality
}

func (n *NilCondition) Marshal() []byte          { return nil } // nothing to marshal
func (n *NilCondition) Unmarshal(b []byte) error { return nil } // nothing to unmarshal

func (n *NilFulfillment) Fulfill(UnlockCondition, FulfillContext) error { return ErrNilFulfillmentType }
func (n *NilFulfillment) Sign(FulfillmentSignContext) error             { return ErrNilFulfillmentType }
func (n *NilFulfillment) UnlockHash() UnlockHash                        { return NilUnlockHash }

func (n *NilFulfillment) Equal(f UnlockFulfillment) bool {
	if f == nil {
		return true // implicit equality
	}
	_, equal := f.(*NilFulfillment)
	return equal // explicit equality
}

func (n *NilFulfillment) FulfillmentType() FulfillmentType { return FulfillmentTypeNil }
func (n *NilFulfillment) IsStandardFulfillment() error     { return ErrNilFulfillmentType } // never valid

func (n *NilFulfillment) Marshal() []byte {
	if build.DEBUG {
		panic(ErrNilFulfillmentType)
	}
	return nil // nothing to marshal
}
func (n *NilFulfillment) Unmarshal([]byte) error { return ErrNilFulfillmentType } // cannot be unmarshalled

func (u *UnknownCondition) ConditionType() ConditionType { return u.Type }
func (u *UnknownCondition) IsStandardCondition() error   { return ErrUnknownConditionType } // never valid

func (u *UnknownCondition) UnlockHash() UnlockHash { return UnknownUnlockHash }

func (u *UnknownCondition) Equal(c UnlockCondition) bool {
	uc, ok := c.(*UnknownCondition)
	if !ok {
		return false
	}
	if u.Type != uc.Type {
		return false
	}
	return bytes.Compare(u.RawCondition[:], uc.RawCondition[:]) == 0
}

func (u *UnknownCondition) Marshal() []byte {
	return u.RawCondition
}
func (u *UnknownCondition) Unmarshal(b []byte) error {
	if len(b) == 0 {
		return errors.New("no bytes given to unmarsal into a raw condition")
	}
	u.RawCondition = b
	return nil
}

func (u *UnknownFulfillment) Fulfill(UnlockCondition, FulfillContext) error { return nil } // always fulfilled
func (u *UnknownFulfillment) Sign(FulfillmentSignContext) error {
	return errors.New("cannot sign fulfillment: " + ErrUnknownFulfillmentType.Error())
}

func (u *UnknownFulfillment) UnlockHash() UnlockHash { return UnknownUnlockHash }

func (u *UnknownFulfillment) Equal(f UnlockFulfillment) bool {
	uf, ok := f.(*UnknownFulfillment)
	if !ok {
		return false
	}
	if u.Type != uf.Type {
		return false
	}
	return bytes.Compare(u.RawFulfillment[:], uf.RawFulfillment[:]) == 0
}

func (u *UnknownFulfillment) FulfillmentType() FulfillmentType { return u.Type }
func (u *UnknownFulfillment) IsStandardFulfillment() error     { return ErrUnknownFulfillmentType } // never valid

func (u *UnknownFulfillment) Marshal() []byte {
	return u.RawFulfillment
}
func (u *UnknownFulfillment) Unmarshal(b []byte) error {
	if len(b) == 0 {
		return errors.New("no bytes given to unmarsal into a raw fulfillment")
	}
	u.RawFulfillment = b
	return nil
}

func (uh *UnlockHashCondition) ConditionType() ConditionType { return ConditionTypeUnlockHash }
func (uh *UnlockHashCondition) IsStandardCondition() error {
	if uh.TargetUnlockHash.Type != UnlockTypePubKey && uh.TargetUnlockHash.Type != UnlockTypeAtomicSwap {
		return errors.New("unsupported unlock type by unlock hash condition")
	}
	if uh.TargetUnlockHash.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	return nil
}

func (uh *UnlockHashCondition) UnlockHash() UnlockHash {
	return uh.TargetUnlockHash
}

func (uh *UnlockHashCondition) Equal(c UnlockCondition) bool {
	ouh, ok := c.(*UnlockHashCondition)
	if !ok {
		return false
	}
	return uh.TargetUnlockHash.Cmp(ouh.TargetUnlockHash) == 0
}

func (uh *UnlockHashCondition) Marshal() []byte {
	return encoding.Marshal(uh.TargetUnlockHash)
}
func (uh *UnlockHashCondition) Unmarshal(b []byte) error {
	return encoding.Unmarshal(b, &uh.TargetUnlockHash)
}

func NewSingleSignatureFulfillment(pk SiaPublicKey) *SingleSignatureFulfillment {
	return &SingleSignatureFulfillment{PublicKey: pk}
}

func (ss *SingleSignatureFulfillment) Fulfill(condition UnlockCondition, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case *UnlockHashCondition:
		uh := ss.UnlockHash()
		if uh != tc.TargetUnlockHash {
			return errors.New("fulfillment provides wrong public key")
		}
		return verifyHashUsingSiaPublicKey(ss.PublicKey,
			ctx.InputIndex, ctx.Transaction, ss.Signature)

	case *NilCondition, nil:
		return verifyHashUsingSiaPublicKey(ss.PublicKey,
			ctx.InputIndex, ctx.Transaction, ss.Signature)

	default:
		return ErrUnexpectedUnlockCondition
	}
}

func (ss *SingleSignatureFulfillment) Sign(ctx FulfillmentSignContext) (err error) {
	if len(ss.Signature) != 0 {
		return ErrFulfillmentDoubleSign
	}

	ss.Signature, err = signHashUsingSiaPublicKey(
		ss.PublicKey, ctx.InputIndex, ctx.Transaction, ctx.Key)
	return
}

func (ss *SingleSignatureFulfillment) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypePubKey, crypto.HashObject(encoding.Marshal(ss.PublicKey)))
}

func (ss *SingleSignatureFulfillment) FulfillmentType() FulfillmentType {
	return FulfillmentTypeSingleSignature
}
func (ss *SingleSignatureFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(ss.PublicKey, ss.Signature)
}

func (ss *SingleSignatureFulfillment) Equal(f UnlockFulfillment) bool {
	oss, ok := f.(*SingleSignatureFulfillment)
	if !ok {
		return false
	}
	if ss.PublicKey.Algorithm != oss.PublicKey.Algorithm {
		return false
	}
	if bytes.Compare(ss.PublicKey.Key[:], oss.PublicKey.Key[:]) != 0 {
		return false
	}
	return bytes.Compare(ss.Signature[:], oss.Signature[:]) == 0
}

func (ss *SingleSignatureFulfillment) Marshal() []byte {
	return encoding.MarshalAll(ss.PublicKey, ss.Signature)
}
func (ss *SingleSignatureFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &ss.PublicKey, &ss.Signature)
}

func (as *AtomicSwapCondition) ConditionType() ConditionType { return ConditionTypeAtomicSwap }
func (as *AtomicSwapCondition) IsStandardCondition() error {
	if as.Sender.Type != UnlockTypePubKey || as.Receiver.Type != UnlockTypePubKey {
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

func (as *AtomicSwapCondition) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeAtomicSwap, crypto.HashObject(as.Marshal()))
}

func (as *AtomicSwapCondition) Equal(c UnlockCondition) bool {
	oas, ok := c.(*AtomicSwapCondition)
	if !ok {
		return false
	}
	if as.TimeLock != oas.TimeLock {
		return false
	}
	if bytes.Compare(as.HashedSecret[:], oas.HashedSecret[:]) != 0 {
		return false
	}
	if as.Sender.Cmp(oas.Sender) != 0 {
		return false
	}
	return as.Receiver.Cmp(oas.Receiver) == 0
}

func (as *AtomicSwapCondition) Marshal() []byte {
	return encoding.MarshalAll(as.Sender, as.Receiver, as.HashedSecret, as.TimeLock)
}
func (as *AtomicSwapCondition) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.Sender, &as.Receiver, &as.HashedSecret, &as.TimeLock)
}

func NewAtomicSwapClaimFulfillment(pk SiaPublicKey, secret AtomicSwapSecret) *AtomicSwapFulfillment {
	return &AtomicSwapFulfillment{
		PublicKey: pk,
		Secret:    secret,
	}
}

func NewAtomicSwapRefundFulfillment(pk SiaPublicKey) *AtomicSwapFulfillment {
	return &AtomicSwapFulfillment{PublicKey: pk}
}

func (as *AtomicSwapFulfillment) Fulfill(condition UnlockCondition, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case *AtomicSwapCondition:
		// create the unlockHash for the given public Ke
		unlockHash := NewUnlockHash(UnlockTypePubKey,
			crypto.HashObject(encoding.Marshal(as.PublicKey)))
		// prior to our timelock, only the receiver can claim the unspend output
		if CurrentTimestamp() <= tc.TimeLock {
			// verify that receiver public key was given
			if unlockHash.Cmp(tc.Receiver) != 0 {
				return ErrInvalidRedeemer
			}

			// verify signature
			err := verifyHashUsingSiaPublicKey(
				as.PublicKey, ctx.InputIndex, ctx.Transaction, as.Signature,
				as.PublicKey, as.Secret)
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
		return verifyHashUsingSiaPublicKey(
			as.PublicKey, ctx.InputIndex, ctx.Transaction, as.Signature,
			as.PublicKey)

	default:
		return ErrUnexpectedUnlockCondition
	}
}

func (as *AtomicSwapFulfillment) Sign(ctx FulfillmentSignContext) error {
	if len(as.Signature) != 0 {
		return ErrFulfillmentDoubleSign
	}

	if as.Secret != (AtomicSwapSecret{}) {
		// sign as claimer
		var err error
		as.Signature, err = signHashUsingSiaPublicKey(
			as.PublicKey, ctx.InputIndex, ctx.Transaction, ctx.Key,
			as.PublicKey, as.Secret)
		return err
	}

	// sign as refunder
	var err error
	as.Signature, err = signHashUsingSiaPublicKey(
		as.PublicKey, ctx.InputIndex, ctx.Transaction, ctx.Key,
		as.PublicKey)
	return err
}

func (as *AtomicSwapFulfillment) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeAtomicSwap, crypto.HashObject(encoding.Marshal(as.PublicKey)))
}

func (as *AtomicSwapFulfillment) FulfillmentType() FulfillmentType { return FulfillmentTypeAtomicSwap }
func (as *AtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as *AtomicSwapFulfillment) Equal(f UnlockFulfillment) bool {
	oas, ok := f.(*AtomicSwapFulfillment)
	if !ok {
		return false
	}
	if as.PublicKey.Algorithm != oas.PublicKey.Algorithm {
		return false
	}
	if bytes.Compare(as.PublicKey.Key[:], oas.PublicKey.Key[:]) != 0 {
		return false
	}
	if bytes.Compare(as.Signature[:], oas.Signature[:]) != 0 {
		return false
	}
	return bytes.Compare(as.Secret[:], oas.Secret[:]) == 0
}

func (as *AtomicSwapFulfillment) Marshal() []byte {
	return encoding.MarshalAll(as.PublicKey, as.Signature, as.Secret)
}
func (as *AtomicSwapFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.PublicKey, &as.Signature, &as.Secret)
}

func (as *AtomicSwapFulfillment) AtomicSwapSecret() AtomicSwapSecret {
	return as.Secret
}

func (as *LegacyAtomicSwapFulfillment) Fulfill(condition UnlockCondition, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case *UnlockHashCondition:
		// ensure the condition equals the ours
		ourHS := as.UnlockHash()
		if ourHS.Cmp(tc.TargetUnlockHash) != 0 {
			return errors.New("produced unlock hash doesn't equal the expected unlock hash")
		}

		// create the unlockHash for the given public Key
		unlockHash := NewSingleSignatureFulfillment(as.PublicKey).UnlockHash()

		// prior to our timelock, only the receiver can claim the unspend output
		if CurrentTimestamp() <= as.TimeLock {
			// verify that receiver public key was given
			if unlockHash.Cmp(as.Receiver) != 0 {
				return ErrInvalidRedeemer
			}

			// verify signature
			err := verifyHashUsingSiaPublicKey(
				as.PublicKey, ctx.InputIndex, ctx.Transaction, as.Signature,
				as.PublicKey, as.Secret)
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
		return verifyHashUsingSiaPublicKey(
			as.PublicKey, ctx.InputIndex, ctx.Transaction, as.Signature,
			as.PublicKey)

	case *AtomicSwapCondition:
		// it's perfectly fine to unlock an atomic swap condition
		// using an atomic swap format in the legacy format,
		// as long as all properties check out
		if tc.Sender.Cmp(as.Sender) != 0 {
			return errors.New("legacy atomic swap fulfillment defines an incorrect sender")
		}
		if tc.Receiver.Cmp(as.Receiver) != 0 {
			return errors.New("legacy atomic swap fulfillment defines an incorrect receiver")
		}
		if tc.TimeLock != as.TimeLock {
			return errors.New("legacy atomic swap fulfillment defines an incorrect time lock")
		}
		if bytes.Compare(tc.HashedSecret[:], as.HashedSecret[:]) != 0 {
			return errors.New("legacy atomic swap fulfillment defines an incorrect hashed secret")
		}

		// delegate logic to the fulfillment in the new format
		return (&AtomicSwapFulfillment{
			PublicKey: as.PublicKey,
			Signature: as.Signature,
			Secret:    as.Secret,
		}).Fulfill(condition, ctx)

	default:
		return ErrUnexpectedUnlockCondition
	}
}

func (as *LegacyAtomicSwapFulfillment) Sign(ctx FulfillmentSignContext) error {
	if len(as.Signature) != 0 {
		return ErrFulfillmentDoubleSign
	}
	if as.Secret != (AtomicSwapSecret{}) {
		if CurrentTimestamp() > as.TimeLock {
			// cannot sign as claimer, when time lock has already been unlocked
			return errors.New("atomic swap contract expired already")
		}

		// sign as claimer
		var err error
		as.Signature, err = signHashUsingSiaPublicKey(
			as.PublicKey, ctx.InputIndex, ctx.Transaction, ctx.Key,
			as.PublicKey, as.Secret)
		return err
	}

	// sign as refunder
	var err error
	as.Signature, err = signHashUsingSiaPublicKey(
		as.PublicKey, ctx.InputIndex, ctx.Transaction, ctx.Key,
		as.PublicKey)
	return err
}

func (as *LegacyAtomicSwapFulfillment) UnlockHash() UnlockHash {
	return NewUnlockHash(UnlockTypeAtomicSwap, crypto.HashObject(encoding.MarshalAll(
		as.Sender,
		as.Receiver,
		as.HashedSecret,
		as.TimeLock,
	)))
}

func (as *LegacyAtomicSwapFulfillment) FulfillmentType() FulfillmentType {
	return FulfillmentTypeAtomicSwap
}
func (as *LegacyAtomicSwapFulfillment) IsStandardFulfillment() error {
	if as.Sender.Type != UnlockTypePubKey || as.Receiver.Type != UnlockTypePubKey {
		return errors.New("unsupported unlock hash type")
	}
	if as.Sender.Hash == (crypto.Hash{}) || as.Receiver.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	if as.HashedSecret == (AtomicSwapHashedSecret{}) {
		return errors.New("nil hashed secret not allowed")
	}
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as *LegacyAtomicSwapFulfillment) Equal(f UnlockFulfillment) bool {
	olas, ok := f.(*LegacyAtomicSwapFulfillment)
	if !ok {
		return false
	}
	if as.TimeLock != olas.TimeLock {
		return false
	}
	if bytes.Compare(as.HashedSecret[:], olas.HashedSecret[:]) != 0 {
		return false
	}
	if as.Sender.Cmp(olas.Sender) != 0 {
		return false
	}
	if as.Receiver.Cmp(olas.Receiver) != 0 {
		return false
	}
	if as.PublicKey.Algorithm != olas.PublicKey.Algorithm {
		return false
	}
	if bytes.Compare(as.PublicKey.Key[:], olas.PublicKey.Key[:]) != 0 {
		return false
	}
	if bytes.Compare(as.Signature[:], olas.Signature[:]) != 0 {
		return false
	}
	return bytes.Compare(as.Secret[:], olas.Secret[:]) == 0
}

func (as *LegacyAtomicSwapFulfillment) Marshal() []byte {
	return encoding.MarshalAll(
		as.Sender, as.Receiver, as.HashedSecret, as.TimeLock,
		as.PublicKey, as.Signature, as.Secret)
}
func (as *LegacyAtomicSwapFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b,
		&as.Sender, &as.Receiver, &as.HashedSecret, &as.TimeLock,
		&as.PublicKey, &as.Signature, &as.Secret)
}

func (as *LegacyAtomicSwapFulfillment) AtomicSwapSecret() AtomicSwapSecret {
	return as.Secret
}

var (
	_ MarshalableUnlockCondition = (*NilCondition)(nil)
	_ MarshalableUnlockCondition = (*UnknownCondition)(nil)
	_ MarshalableUnlockCondition = (*UnlockHashCondition)(nil)
	_ MarshalableUnlockCondition = (*AtomicSwapCondition)(nil)

	_ MarshalableUnlockFulfillment = (*NilFulfillment)(nil)
	_ MarshalableUnlockFulfillment = (*UnknownFulfillment)(nil)
	_ MarshalableUnlockFulfillment = (*SingleSignatureFulfillment)(nil)
	_ MarshalableUnlockFulfillment = (*AtomicSwapFulfillment)(nil)
	_ MarshalableUnlockFulfillment = (*LegacyAtomicSwapFulfillment)(nil)
)

// NewAtomicSwapHashedSecret creates a new atomic swap hashed secret,
// using a pre-generated atomic swap secret.
func NewAtomicSwapHashedSecret(secret AtomicSwapSecret) AtomicSwapHashedSecret {
	return AtomicSwapHashedSecret(sha256.Sum256(secret[:]))
}

// String turns this hashed secret into a hex-formatted string.
func (hs AtomicSwapHashedSecret) String() string {
	return hex.EncodeToString(hs[:])
}

// LoadString loads a hashed secret from a hex-formatted string.
func (hs *AtomicSwapHashedSecret) LoadString(str string) error {
	n, err := hex.Decode(hs[:], []byte(str))
	if err != nil {
		return err
	}
	if n != AtomicSwapHashedSecretLen {
		return errors.New("invalid (atomic-swap) hashed secret length")
	}
	return nil
}

// MarshalJSON marshals a hashed secret as a hex string.
func (hs AtomicSwapHashedSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(hs.String())
}

// UnmarshalJSON decodes the json string of the hashed secret.
func (hs *AtomicSwapHashedSecret) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	return hs.LoadString(str)
}

var (
	_ json.Marshaler   = AtomicSwapHashedSecret{}
	_ json.Unmarshaler = (*AtomicSwapHashedSecret)(nil)
)

// NewAtomicSwapSecret creates a new cryptographically secure
// atomic swap secret
func NewAtomicSwapSecret() (ass AtomicSwapSecret, err error) {
	_, err = rand.Read(ass[:])
	return
}

// String turns this secret into a hex-formatted string.
func (s AtomicSwapSecret) String() string {
	return hex.EncodeToString(s[:])
}

// LoadString loads a secret from a hex-formatted string.
func (s *AtomicSwapSecret) LoadString(str string) error {
	n, err := hex.Decode(s[:], []byte(str))
	if err != nil {
		return err
	}
	if n != AtomicSwapSecretLen {
		return errors.New("invalid (atomic-swap) secret length")
	}
	return nil
}

// MarshalJSON marshals a secret as a hex string.
func (s AtomicSwapSecret) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON decodes the json string of the secret.
func (s *AtomicSwapSecret) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return err
	}
	return s.LoadString(str)
}

var (
	_ json.Marshaler   = AtomicSwapSecret{}
	_ json.Unmarshaler = (*AtomicSwapSecret)(nil)
)

func (as *anyAtomicSwapFulfillment) Unmarshal(b []byte) error {
	asf := new(AtomicSwapFulfillment)
	// be positive, first try the new format
	err := encoding.Unmarshal(b, asf)
	if err == nil {
		as.MarshalableUnlockFulfillment = asf
		return nil
	}

	// didn't work out, let's try the legacy atomic swap fulfillment
	lasf := new(LegacyAtomicSwapFulfillment)
	err = encoding.Unmarshal(b, lasf)
	as.MarshalableUnlockFulfillment = lasf
	return err
}

func (as *anyAtomicSwapFulfillment) MarshalJSON() ([]byte, error) {
	return json.Marshal(as.MarshalableUnlockFulfillment)
}
func (as *anyAtomicSwapFulfillment) UnmarshalJSON(b []byte) error {
	lasf := new(LegacyAtomicSwapFulfillment)
	err := json.Unmarshal(b, lasf)
	if err != nil {
		return err
	}
	var undefOptArgCount uint8
	if lasf.Sender.Cmp(UnlockHash{}) == 0 {
		undefOptArgCount++
	}
	if lasf.Receiver.Cmp(UnlockHash{}) == 0 {
		undefOptArgCount++
	}
	if lasf.TimeLock == 0 {
		undefOptArgCount++
	}
	if nilHS := (AtomicSwapHashedSecret{}); bytes.Compare(lasf.HashedSecret[:], nilHS[:]) == 0 {
		undefOptArgCount++
	}
	switch undefOptArgCount {
	case 0:
		as.MarshalableUnlockFulfillment = lasf
	case 4:
		as.MarshalableUnlockFulfillment = &AtomicSwapFulfillment{
			PublicKey: lasf.PublicKey,
			Signature: lasf.Signature,
			Secret:    lasf.Secret,
		}
	default:
		return errors.New("when an atomic swap fulfillment defines any of the legacy properties, all of them have to be given")
	}
	return nil
}

var (
	_ MarshalableUnlockFulfillment = (*anyAtomicSwapFulfillment)(nil)
)

func (ct ConditionType) MarshalSia(w io.Writer) error {
	_, err := w.Write([]byte{byte(ct)})
	return err
}

func (ct *ConditionType) UnmarshalSia(r io.Reader) error {
	var b [1]byte
	_, err := r.Read(b[:])
	*ct = ConditionType(b[0])
	return err
}

func (ft FulfillmentType) MarshalSia(w io.Writer) error {
	_, err := w.Write([]byte{byte(ft)})
	return err
}

func (ft *FulfillmentType) UnmarshalSia(r io.Reader) error {
	var b [1]byte
	_, err := r.Read(b[:])
	*ft = FulfillmentType(b[0])
	return err
}

func (up UnlockConditionProxy) ConditionType() ConditionType {
	condition := up.Condition
	if condition == nil {
		condition = &NilCondition{}
	}
	return condition.ConditionType()
}

func (up UnlockConditionProxy) IsStandardCondition() error {
	condition := up.Condition
	if condition == nil {
		condition = &NilCondition{}
	}
	return condition.IsStandardCondition()
}

func (up UnlockConditionProxy) UnlockHash() UnlockHash {
	condition := up.Condition
	if condition == nil {
		condition = &NilCondition{}
	}
	return condition.UnlockHash()
}

func (up UnlockConditionProxy) Equal(o UnlockCondition) bool {
	condition := up.Condition
	if condition == nil {
		condition = &NilCondition{}
	}
	if p, ok := o.(UnlockConditionProxy); ok {
		o = p.Condition
	}
	return condition.Equal(o)
}

func (fp UnlockFulfillmentProxy) Fulfill(condition UnlockCondition, ctx FulfillContext) error {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	if p, ok := condition.(UnlockConditionProxy); ok {
		condition = p.Condition
		if condition == nil {
			condition = &NilCondition{}
		}
	}
	return fulfillment.Fulfill(condition, ctx)
}

func (fp UnlockFulfillmentProxy) Sign(ctx FulfillmentSignContext) error {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	return fulfillment.Sign(ctx)
}

func (fp UnlockFulfillmentProxy) UnlockHash() UnlockHash {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	return fulfillment.UnlockHash()
}

func (fp UnlockFulfillmentProxy) FulfillmentType() FulfillmentType {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	return fulfillment.FulfillmentType()
}

func (fp UnlockFulfillmentProxy) IsStandardFulfillment() error {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	return fulfillment.IsStandardFulfillment()
}

func (fp UnlockFulfillmentProxy) Equal(f UnlockFulfillment) bool {
	fulfillment := fp.Fulfillment
	if fulfillment == nil {
		fulfillment = &NilFulfillment{}
	}
	if p, ok := f.(UnlockFulfillmentProxy); ok {
		f = p.Fulfillment
	}
	return fulfillment.Equal(f)
}

func (up UnlockConditionProxy) MarshalSia(w io.Writer) error {
	encoder := encoding.NewEncoder(w)
	if up.Condition == nil {
		return encoder.EncodeAll(ConditionTypeNil, 0) // type + nil-slice
	}
	return encoding.NewEncoder(w).EncodeAll(
		up.Condition.ConditionType(), up.Condition.Marshal())
}

func (up *UnlockConditionProxy) UnmarshalSia(r io.Reader) error {
	var (
		t  ConditionType
		rc []byte
	)
	err := encoding.NewDecoder(r).DecodeAll(&t, &rc)
	if err != nil {
		return err
	}
	cc, ok := _RegisteredUnlockConditionTypes[t]
	if !ok {
		up.Condition = &UnknownCondition{
			Type:         t,
			RawCondition: rc,
		}
		return nil
	}
	c := cc()
	err = c.Unmarshal(rc)
	up.Condition = c
	return err
}

func (fp UnlockFulfillmentProxy) MarshalSia(w io.Writer) error {
	encoder := encoding.NewEncoder(w)
	if fp.Fulfillment == nil {
		return encoder.EncodeAll(FulfillmentTypeNil, 0) // type + nil-slice
	}
	return encoding.NewEncoder(w).EncodeAll(
		fp.Fulfillment.FulfillmentType(), fp.Fulfillment.Marshal())
}

func (fp *UnlockFulfillmentProxy) UnmarshalSia(r io.Reader) error {
	var (
		t  FulfillmentType
		rf []byte
	)
	err := encoding.NewDecoder(r).DecodeAll(&t, &rf)
	if err != nil {
		return err
	}
	fc, ok := _RegisteredUnlockFulfillmentTypes[t]
	if !ok {
		fp.Fulfillment = &UnknownFulfillment{
			Type:           t,
			RawFulfillment: rf,
		}
		return nil
	}
	f := fc()
	err = f.Unmarshal(rf)
	fp.Fulfillment = f
	return err
}

var (
	_ encoding.SiaMarshaler   = UnlockConditionProxy{}
	_ encoding.SiaUnmarshaler = (*UnlockConditionProxy)(nil)

	_ encoding.SiaMarshaler   = UnlockFulfillmentProxy{}
	_ encoding.SiaUnmarshaler = (*UnlockFulfillmentProxy)(nil)
)

type (
	unlockConditionJSONFormat struct {
		Type ConditionType   `json:"type,omitempty"`
		Data json.RawMessage `json:"data,omitempty"`
	}
	unlockConditionJSONFormatWithNilData struct {
		Type ConditionType `json:"type,omitempty"`
	}
	unlockFulfillmentJSONFormat struct {
		Type FulfillmentType `json:"type,omitempty"`
		Data json.RawMessage `json:"data,omitempty"`
	}
	unlockFulfillmentJSONFormatWithNilData struct {
		Type FulfillmentType `json:"type,omitempty"`
	}
)

func (up UnlockConditionProxy) MarshalJSON() ([]byte, error) {
	if up.Condition == nil {
		return json.Marshal(unlockConditionJSONFormat{
			Type: ConditionTypeNil,
			Data: nil,
		})
	}
	data, err := json.Marshal(up.Condition)
	if err != nil {
		return nil, err
	}
	if string(data) == "{}" {
		return json.Marshal(unlockConditionJSONFormatWithNilData{
			Type: up.Condition.ConditionType(),
		})
	}
	return json.Marshal(unlockConditionJSONFormat{
		Type: up.Condition.ConditionType(),
		Data: data,
	})
}

func (up *UnlockConditionProxy) UnmarshalJSON(b []byte) error {
	var rf unlockConditionJSONFormat
	err := json.Unmarshal(b, &rf)
	if err != nil {
		return err
	}
	cc, ok := _RegisteredUnlockConditionTypes[rf.Type]
	if !ok {
		return ErrUnknownConditionType
	}
	c := cc()
	if rf.Data != nil {
		err = json.Unmarshal(rf.Data, &c)
	}
	up.Condition = c
	return err
}

func (fp UnlockFulfillmentProxy) MarshalJSON() ([]byte, error) {
	if fp.Fulfillment == nil {
		return json.Marshal(unlockFulfillmentJSONFormat{
			Type: FulfillmentTypeNil,
			Data: nil,
		})
	}
	data, err := json.Marshal(fp.Fulfillment)
	if err != nil {
		return nil, err
	}
	if string(data) == "{}" {
		return json.Marshal(unlockFulfillmentJSONFormatWithNilData{
			Type: fp.Fulfillment.FulfillmentType(),
		})
	}
	return json.Marshal(unlockFulfillmentJSONFormat{
		Type: fp.Fulfillment.FulfillmentType(),
		Data: data,
	})
}

func (fp *UnlockFulfillmentProxy) UnmarshalJSON(b []byte) error {
	var rf unlockFulfillmentJSONFormat
	err := json.Unmarshal(b, &rf)
	if err != nil {
		return err
	}
	fc, ok := _RegisteredUnlockFulfillmentTypes[rf.Type]
	if !ok {
		return ErrUnknownFulfillmentType
	}
	f := fc()
	if rf.Data != nil {
		err = json.Unmarshal(rf.Data, &f)
	}
	fp.Fulfillment = f
	return err
}

var (
	_ json.Marshaler   = UnlockConditionProxy{}
	_ json.Unmarshaler = (*UnlockConditionProxy)(nil)

	_ json.Marshaler   = UnlockFulfillmentProxy{}
	_ json.Unmarshaler = (*UnlockFulfillmentProxy)(nil)
)

var (
	_ UnlockCondition   = UnlockConditionProxy{}
	_ UnlockFulfillment = UnlockFulfillmentProxy{}
)

func strictSignatureCheck(pk SiaPublicKey, signature ByteSlice) error {
	switch pk.Algorithm {
	case SignatureEntropy:
		return ErrEntropyKey
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
