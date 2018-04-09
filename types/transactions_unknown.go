package types

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

var (
	// ErrUnknownTransactionVersion is an error returned in places,
	// where having an unknown transaction version makes it unable to proceed.
	// (e.g. strict validation, json encoding, ...)
	ErrUnknownTransactionVersion = errors.New("transaction has an unknown version")
)

// RawTransactionData is the type used to represent in-memory transaction's data,
// which parent transaction has an unknown version.
type RawTransactionData struct {
	RawData []byte
}

var (
	_ TransactionData = (*RawTransactionData)(nil)
)

// CoinInputs implements Transaction.CoinInputs
func (t *RawTransactionData) CoinInputs() []CoinInput { return nil }

// CoinOutputs implements Transaction.CoinOutputs
func (t *RawTransactionData) CoinOutputs() []CoinOutput { return nil }

// BlockStakeInputs implements Transaction.BlockStakeInputs
func (t *RawTransactionData) BlockStakeInputs() []BlockStakeInput { return nil }

// BlockStakeOutputs implements Transaction.BlockStakeOutputs
func (t *RawTransactionData) BlockStakeOutputs() []BlockStakeOutput { return nil }

// MinerFees implements Transaction.MinerFees
func (t *RawTransactionData) MinerFees() []Currency { return nil }

// ValidateTransaction implements Transaction.ValidateTransaction
func (t *RawTransactionData) ValidateTransaction(ctx TransactionValidationContext) error {
	if ctx.Strict {
		return ErrUnknownTransactionVersion
	}
	return nil
}

// InputSigHash implements Transaction.InputSigHash
func (t *RawTransactionData) InputSigHash(uint64, ...interface{}) crypto.Hash { return crypto.Hash{} }

// MarshalSia implements TransactionData.SiaMarshaler.MarshalSia
func (t *RawTransactionData) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).Encode(t.RawData)
}

// UnmarshalSia implements TransactionData.SiaUnmarshaler.UnmarshalSia
func (t *RawTransactionData) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r).Decode(&t.RawData)
}

var (
	_ encoding.SiaMarshaler   = (*TransactionDataV0)(nil)
	_ encoding.SiaUnmarshaler = (*TransactionDataV0)(nil)
)

// MarshalJSON implements TransactionData.JSONMarshaler.MarshalJSON
func (t *RawTransactionData) MarshalJSON() ([]byte, error) {
	return nil, ErrUnknownTransactionVersion
}

// UnmarshalJSON implements TransactionData.JSONUnmarshaler.UnmarshalJSON
func (t *RawTransactionData) UnmarshalJSON(b []byte) error {
	return ErrUnknownTransactionVersion
}

var (
	_ json.Marshaler   = (*RawTransactionData)(nil)
	_ json.Unmarshaler = (*RawTransactionData)(nil)
)
