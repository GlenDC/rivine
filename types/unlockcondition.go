package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

// TODO: ensure we can fulfill legacy conditions

type (
	UnlockCondition interface {
		ConditionType() ConditionType
		IsStandardCondition() error

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockFulfillment interface {
		Fulfill(condition interface{}, ctx FulfillContext) error

		FulfillmentType() FulfillmentType
		IsStandardFulfillment() error

		Marshal() []byte
		Unmarshal([]byte) error
	}

	UnlockConditionProxy struct {
		UnlockCondition
	}
	UnlockFulfillmentProxy struct {
		UnlockFulfillment
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

	// ErrUnknownUnlockType is an error returned in case
	// one tries to use an input lock of unknown type where it's not supported
	ErrUnknownUnlockType = errors.New("unknown unlock type")

	ErrUnknownConditionType   = errors.New("unknown condition type")
	ErrUnknownFulfillmentType = errors.New("unknown fulfillment type")

	// ErrUnknownSignAlgorithmType is an error returned in case
	// one tries to sign using an unknown signing algorithm type.
	//
	// NOTE That verification of unknown signing algorithm types does always succeed!
	ErrUnknownSignAlgorithmType = errors.New("unknown signature algorithm type")
)

func RegisterUnlockConditionConstructor(ct ConditionType, cc UnlockConditionConstructor) {
	if cc == nil {
		delete(_RegisteredUnlockConditionConstructors, ct)
	}
	_RegisteredUnlockConditionConstructors[ct] = cc
}

func RegisterUnlockFulfillmentConstructor(ft FulfillmentType, fc UnlockFulfillmentConstructor) {
	if fc == nil {
		delete(_RegisteredUnlockFulfillmentConstructors, ft)
	}
	_RegisteredUnlockFulfillmentConstructors[ft] = fc
}

type (
	UnlockConditionConstructor   func() UnlockCondition
	UnlockFulfillmentConstructor func() UnlockFulfillment
)

var (
	_RegisteredUnlockConditionConstructors = map[ConditionType]UnlockConditionConstructor{
		ConditionTypeNil:        func() UnlockCondition { return &NilCondition{} },
		ConditionTypeUnlockHash: func() UnlockCondition { return &UnlockHashCondition{} },
		ConditionTypeAtomicSwap: func() UnlockCondition { return &AtomicSwapCondition{} },
	}
	_RegisteredUnlockFulfillmentConstructors = map[FulfillmentType]UnlockFulfillmentConstructor{
		FulfillmentTypeNil:             func() UnlockFulfillment { return &NilFulfillment{} },
		FulfillmentTypeSingleSignature: func() UnlockFulfillment { return &SingleSignatureFulfillment{} },
		FulfillmentTypeAtomicSwap:      func() UnlockFulfillment { return &AtomicSwapFulfillment{} },
	}
)

type (
	NilCondition   struct{}
	NilFulfillment struct{}

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

func (n *NilCondition) ConditionType() ConditionType { return ConditionTypeNil }
func (n *NilCondition) IsStandardCondition() error   { return nil } // always valid

func (n *NilCondition) Marshal() []byte          { return nil } // nothing to marshal
func (n *NilCondition) Unmarshal(b []byte) error { return nil } // nothing to unmarshal

func (n *NilFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (n *NilFulfillment) FulfillmentType() FulfillmentType          { return FulfillmentTypeNil }
func (n *NilFulfillment) IsStandardFulfillment() error              { return nil } // always valid

func (n *NilFulfillment) Marshal() []byte          { return nil } // nothing to marshal
func (n *NilFulfillment) Unmarshal(b []byte) error { return nil } // nothing to unmarshal

func (u *UnknownCondition) ConditionType() ConditionType { return u.Type }
func (u *UnknownCondition) IsStandardCondition() error   { return ErrUnknownUnlockType } // never valid

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

func (u *UnknownFulfillment) Fulfill(interface{}, FulfillContext) error { return nil } // always fulfilled
func (u *UnknownFulfillment) FulfillmentType() FulfillmentType          { return u.Type }
func (u *UnknownFulfillment) IsStandardFulfillment() error              { return ErrUnknownUnlockType } // never valid

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
	if uh.TargetUnlockHash.Type != UnlockTypeSingleSignature && uh.TargetUnlockHash.Type != UnlockTypeAtomicSwap {
		return errors.New("unsupported unlock type by unlock hash condition")
	}
	if uh.TargetUnlockHash.Hash == (crypto.Hash{}) {
		return errors.New("nil crypto hash cannot be used as unlock hash")
	}
	return nil
}

func (uh *UnlockHashCondition) Marshal() []byte {
	return encoding.Marshal(uh.TargetUnlockHash)
}
func (uh *UnlockHashCondition) Unmarshal(b []byte) error {
	return encoding.Unmarshal(b, &uh.TargetUnlockHash)
}

func NewSingleSignatureFulfillment() (SingleSignatureFulfillment, error) {
	panic("TODO")
}

func (ss *SingleSignatureFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
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
func (ss *SingleSignatureFulfillment) FulfillmentType() FulfillmentType {
	return FulfillmentTypeSingleSignature
}
func (ss *SingleSignatureFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(ss.PublicKey, ss.Signature)
}

func (ss *SingleSignatureFulfillment) Marshal() []byte {
	return encoding.MarshalAll(ss.PublicKey, ss.Signature)
}
func (ss *SingleSignatureFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &ss.PublicKey, &ss.Signature)
}

func (as *AtomicSwapCondition) ConditionType() ConditionType { return ConditionTypeAtomicSwap }
func (as *AtomicSwapCondition) IsStandardCondition() error {
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

func (as *AtomicSwapCondition) Marshal() []byte {
	return encoding.MarshalAll(as.Sender, as.Receiver, as.HashedSecret, as.TimeLock)
}
func (as *AtomicSwapCondition) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.Sender, &as.Receiver, &as.HashedSecret, &as.TimeLock)
}

func NewAtomicSwapClaimFulfillment() (AtomicSwapFulfillment, error) {
	panic("TODO")
}

func NewAtomicSwapRefundFulfillment() (AtomicSwapFulfillment, error) {
	panic("TODO")
}

func (as *AtomicSwapFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case AtomicSwapCondition:
		// create the unlockHash for the given public Ke
		unlockHash := NewUnlockHash(UnlockTypeSingleSignature,
			crypto.HashObject(encoding.Marshal(as.PublicKey)))
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
func (as *AtomicSwapFulfillment) FulfillmentType() FulfillmentType { return FulfillmentTypeAtomicSwap }
func (as *AtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as *AtomicSwapFulfillment) Marshal() []byte {
	return encoding.MarshalAll(as.PublicKey, as.Signature, as.Secret)
}
func (as *AtomicSwapFulfillment) Unmarshal(b []byte) error {
	return encoding.UnmarshalAll(b, &as.PublicKey, &as.Signature, &as.Secret)
}

func (as *LegacyAtomicSwapFulfillment) Fulfill(condition interface{}, ctx FulfillContext) error {
	switch tc := condition.(type) {
	case UnlockHashCondition:
		// ensure the condition equals the ours
		ourHS := NewUnlockHash(UnlockTypeAtomicSwap, crypto.HashObject(encoding.MarshalAll(
			as.Sender,
			as.Receiver,
			as.HashedSecret,
			as.TimeLock,
		)))
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
func (as *LegacyAtomicSwapFulfillment) FulfillmentType() FulfillmentType {
	return FulfillmentTypeAtomicSwap
}
func (as *LegacyAtomicSwapFulfillment) IsStandardFulfillment() error {
	return strictSignatureCheck(as.PublicKey, as.Signature)
}

func (as *LegacyAtomicSwapFulfillment) Marshal() []byte {
	return nil // not supported in legacy fulfillment
}
func (as *LegacyAtomicSwapFulfillment) Unmarshal(b []byte) error {
	return errors.New("unmarshal feature not supported in legacy fulfillment")
}

var (
	_ UnlockCondition = (*NilCondition)(nil)
	_ UnlockCondition = (*UnknownCondition)(nil)
	_ UnlockCondition = (*UnlockHashCondition)(nil)
	_ UnlockCondition = (*AtomicSwapCondition)(nil)

	_ UnlockFulfillment = (*NilFulfillment)(nil)
	_ UnlockFulfillment = (*UnknownFulfillment)(nil)
	_ UnlockFulfillment = (*SingleSignatureFulfillment)(nil)
	_ UnlockFulfillment = (*AtomicSwapFulfillment)(nil)
	_ UnlockFulfillment = (*LegacyAtomicSwapFulfillment)(nil)
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

func (up UnlockConditionProxy) MarshalSia(w io.Writer) error {
	encoder := encoding.NewEncoder(w)
	if up.UnlockCondition == nil {
		return encoder.EncodeAll(ConditionTypeNil, 0) // type + nil-slice
	}
	return encoding.NewEncoder(w).EncodeAll(
		up.UnlockCondition.ConditionType(), up.UnlockCondition.Marshal())
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
	cc, ok := _RegisteredUnlockConditionConstructors[t]
	if !ok {
		up.UnlockCondition = &UnknownCondition{
			Type:         t,
			RawCondition: rc,
		}
		return nil
	}
	c := cc()
	err = c.Unmarshal(rc)
	up.UnlockCondition = c
	return err
}

func (fp UnlockFulfillmentProxy) MarshalSia(w io.Writer) error {
	encoder := encoding.NewEncoder(w)
	if fp.UnlockFulfillment == nil {
		return encoder.EncodeAll(FulfillmentTypeNil, 0) // type + nil-slice
	}
	return encoding.NewEncoder(w).EncodeAll(
		fp.UnlockFulfillment.FulfillmentType(), fp.UnlockFulfillment.Marshal())
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
	fc, ok := _RegisteredUnlockFulfillmentConstructors[t]
	if !ok {
		fp.UnlockFulfillment = &UnknownFulfillment{
			Type:           t,
			RawFulfillment: rf,
		}
		return nil
	}
	f := fc()
	err = f.Unmarshal(rf)
	fp.UnlockFulfillment = f
	return err
}

var (
	_ encoding.SiaMarshaler   = UnlockConditionProxy{}
	_ encoding.SiaUnmarshaler = (*UnlockConditionProxy)(nil)

	_ encoding.SiaMarshaler   = UnlockFulfillmentProxy{}
	_ encoding.SiaUnmarshaler = (*UnlockFulfillmentProxy)(nil)
)

type unlockConditionJSONFormat struct {
	Type ConditionType   `json:"type,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type unlockConditionJSONFormatWithNilData struct {
	Type ConditionType `json:"type,omitempty"`
}

type unlockFulfillmentJSONFormat struct {
	Type FulfillmentType `json:"type,omitempty"`
	Data json.RawMessage `json:"data,omitempty"`
}

type unlockFulfillmentJSONFormatWithNilData struct {
	Type FulfillmentType `json:"type,omitempty"`
}

func (up UnlockConditionProxy) MarshalJSON() ([]byte, error) {
	if up.UnlockCondition == nil {
		return json.Marshal(unlockConditionJSONFormat{
			Type: ConditionTypeNil,
			Data: nil,
		})
	}
	data, err := json.Marshal(up.UnlockCondition)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if string(data) == "{}" {
		return json.Marshal(unlockConditionJSONFormatWithNilData{
			Type: up.UnlockCondition.ConditionType(),
		})
	}
	return json.Marshal(unlockConditionJSONFormat{
		Type: up.UnlockCondition.ConditionType(),
		Data: data,
	})
}

func (up *UnlockConditionProxy) UnmarshalJSON(b []byte) error {
	var rf unlockConditionJSONFormat
	err := json.Unmarshal(b, &rf)
	if err != nil {
		return err
	}
	cc, ok := _RegisteredUnlockConditionConstructors[rf.Type]
	if !ok {
		return ErrUnknownConditionType
	}
	c := cc()
	if rf.Data != nil {
		err = json.Unmarshal(rf.Data, &c)
	}
	up.UnlockCondition = c
	return err
}

func (fp UnlockFulfillmentProxy) MarshalJSON() ([]byte, error) {
	if fp.UnlockFulfillment == nil {
		return json.Marshal(unlockFulfillmentJSONFormat{
			Type: FulfillmentTypeNil,
			Data: nil,
		})
	}
	data, err := json.Marshal(fp.UnlockFulfillment)
	if err != nil {
		return nil, err
	}
	if string(data) == "{}" {
		return json.Marshal(unlockFulfillmentJSONFormatWithNilData{
			Type: fp.UnlockFulfillment.FulfillmentType(),
		})
	}
	return json.Marshal(unlockFulfillmentJSONFormat{
		Type: fp.UnlockFulfillment.FulfillmentType(),
		Data: data,
	})
}

func (fp *UnlockFulfillmentProxy) UnmarshalJSON(b []byte) error {
	var rf unlockFulfillmentJSONFormat
	err := json.Unmarshal(b, &rf)
	if err != nil {
		return err
	}
	fc, ok := _RegisteredUnlockFulfillmentConstructors[rf.Type]
	if !ok {
		return ErrUnknownFulfillmentType
	}
	f := fc()
	if rf.Data != nil {
		err = json.Unmarshal(rf.Data, &f)
	}
	fp.UnlockFulfillment = f
	return err
}

var (
	_ json.Marshaler   = UnlockConditionProxy{}
	_ json.Unmarshaler = (*UnlockConditionProxy)(nil)

	_ json.Marshaler   = UnlockFulfillmentProxy{}
	_ json.Unmarshaler = (*UnlockFulfillmentProxy)(nil)
)

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
