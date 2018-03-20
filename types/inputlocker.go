package types

import (
	"errors"

	"github.com/rivine/rivine/crypto"
)

type (
	// InputUnlocker defines the logic to unlock Coins and Blockstakes.
	// In other words, it ensures that the given Input matches the previous Output.
	InputUnlocker interface {
		// UnlockCoinInput attempts to unlock the given coins,
		// returning an error if not possible and nil otherwise.
		UnlockCoinInput(input CoinInput, output CoinOutput) error
		// UnlockBlockstakeInput attempts to unlock the given block stake,
		// returning an error if not possible and nil otherwise.
		UnlockBlockstakeInput(input BlockStakeInput, output BlockStakeOutput) error
	}

	// UnlockType defines the type of an InputUnlocker,
	// which is used to unlock coins and block stakes.
	UnlockType byte
)

const (
	// UnlockTypeSignature provides the standard and most simple unlock type.
	// In it the sender gives the public key of the intendend receiver.
	// The receiver can redeem the relevant locked input by providing a signature
	// which proofs the ownership of the private key linked to the known public key.
	UnlockTypeSignature UnlockType = iota + 1

	// MaxStandardUnlockType can be used to define your own
	// UnlockType without having to hardcode the final standard
	// unlock type, while still preventing any possible type overwrite.
	MaxStandardUnlockType = UnlockTypeSignature
)

// InputUnlocker errors
var (
	ErrInvalidUnlockType        = errors.New("invalid unlock type")
	ErrInvalidUnlockCondition   = errors.New("invalid unlock condition")
	ErrInvalidUnlockFulfillment = errors.New("invalid unlock fulfillment")
)

// GetInputUnlocker gets the correct (registered)
// input locker for the given UnlockType.
func GetInputUnlocker(t UnlockType) (InputUnlocker, error) {
	unlocker, found := _RegisteredInputUnlockers[t]
	if !found {
		return nil, ErrInvalidUnlockType
	}
	return unlocker, nil
}

// _RegisteredInputUnlockers contains all known/registered input unlockers.
var _RegisteredInputUnlockers = map[UnlockType]InputUnlocker{}

// RegisterInputUnlocker registers the given non-nil input locker,
// for the given UnlockType, essentially linking the given locker to the given type.
func RegisterInputUnlocker(t UnlockType, u InputUnlocker) {
	if u == nil {
		panic("cannot register nil InputUnlocker")
	}
	_RegisteredInputUnlockers[t] = u
}

// UnregisterInputUnlocker unregisters the given UnlockType,
// meaning the given UnlockType will no longer have a matching InputUnlocker.
func UnregisterInputUnlocker(t UnlockType) {
	delete(_RegisteredInputUnlockers, t)
}

// SignatureInputUnlocker provides the standard and most simple input unlocker implementation.
// In it the sender gives the public key of the intendend receiver.
// The receiver can redeem the relevant locked input by providing a signature
// which proofs the ownership of the private key linked to the known public key.
type SignatureInputUnlocker struct{}

// UnlockCoinInput implements InputUnlocker.UnlockCoinInput
func (siu SignatureInputUnlocker) UnlockCoinInput(input CoinInput, output CoinOutput) error {
	if len(output.UnlockCondition.Condition) != crypto.PublicKeySize {
		return ErrInvalidUnlockCondition
	}
	var pubKey crypto.PublicKey
	copy(pubKey[:], output.UnlockCondition.Condition)

	if len(input.UnlockFulfillment.Fulfillment) != crypto.SignatureSize {
		return ErrInvalidUnlockFulfillment
	}
	var sig crypto.Signature
	copy(sig[:], input.UnlockFulfillment.Fulfillment)

	err = crypto.VerifyHash(crypto.HashObject(output), pubKey, sig)
	if err != nil {
		return ErrInvalidUnlockFulfillment
	}

	return nil
}

// UnlockBlockstakeInput implements InputUnlocker.UnlockBlockstakeInput
func (siu SignatureInputUnlocker) UnlockBlockstakeInput(input BlockStakeInput, output BlockStakeOutput) error {
	if len(output.UnlockCondition.Condition) != crypto.PublicKeySize {
		return ErrInvalidUnlockCondition
	}
	var pubKey crypto.PublicKey
	copy(pubKey[:], output.UnlockCondition.Condition)

	if len(input.UnlockFulfillment.Fulfillment) != crypto.SignatureSize {
		return ErrInvalidUnlockFulfillment
	}
	var sig crypto.Signature
	copy(sig[:], input.UnlockFulfillment.Fulfillment)

	err = crypto.VerifyHash(crypto.HashObject(output), pubKey, sig)
	if err != nil {
		return ErrInvalidUnlockFulfillment
	}

	return nil
}

// NewSignatureCoinFulfillment returns the fulfillment that should
// allow for the unlocking of the given coin output.
func NewSignatureCoinFulfillment(key crypto.SecretKey, output CoinOutput) UnlockFulfillment {
	return UnlockFulfillment{
		Type:        UnlockTypeSignature,
		Fulfillment: crypto.SignHash(crypto.HashObject(output), key)[:],
	}
}

// NewSignatureBlockStakeFulfillment returns the fulfillment that should
// allow for the unlocking of the given block stake output.
func NewSignatureBlockStakeFulfillment(key crypto.SecretKey, output BlockStakeOutput) UnlockFulfillment {
	return UnlockFulfillment{
		Type:        UnlockTypeSignature,
		Fulfillment: crypto.SignHash(crypto.HashObject(output), key)[:],
	}
}

// NewSignatureUnlockCondition returns the condition that should
// allow for the locking of coins, only unlockable by whoever owns the
// matching (ed25519) private key.
func NewSignatureUnlockCondition(key crypto.PublicKey) UnlockCondition {
	return UnlockCondition{
		Type:      UnlockTypeSignature,
		Condition: key[:],
	}
}

func init() {
	// register standard Rivine InputUnlockers
	RegisterInputUnlocker(UnlockTypeSignature, SignatureInputUnlocker{})
}
