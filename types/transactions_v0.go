package types

import (
	"encoding/json"
	"io"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

type (
	// TransactionDataV0 defines the structure and logic for the data of 0x00 transactions.
	// This is the original and awas t launch only version number known.
	// Now it is deprecate and should be always replaced by 0x01 transactions.
	TransactionDataV0 struct {
		coinInputs        []CoinInput
		coinOutputs       []CoinOutput
		blockStakeInputs  []BlockStakeInput
		blockStakeOutputs []BlockStakeOutput
		minerFees         []Currency
		arbitraryData     []byte
	}

	// TransactionDataV0Config is used to create a new Transaction of version 0x00 (v0)
	TransactionDataV0Config struct {
		CoinInputs        []CoinInput
		CoinOutputs       []CoinOutput
		BlockStakeInputs  []BlockStakeInput
		BlockStakeOutputs []BlockStakeOutput
		MinerFees         []Currency
		ArbitraryData     []byte
	}
)

// NewTransactionV0 creates a new Transaction of version one (legacy).
func NewTransactionV0(cfg TransactionDataV0Config) Transaction {
	return NewTransaction(TransactionVersionOne, &TransactionDataV0{
		coinInputs:        cfg.CoinInputs,
		coinOutputs:       cfg.CoinOutputs,
		blockStakeInputs:  cfg.BlockStakeInputs,
		blockStakeOutputs: cfg.BlockStakeOutputs,
		minerFees:         cfg.MinerFees,
		arbitraryData:     cfg.ArbitraryData,
	})
}

// CoinInputs implements TransactionData.CoinInputs
func (t *TransactionDataV0) CoinInputs() []CoinInput {
	return t.coinInputs
}

// CoinOutputs implements TransactionData.CoinOutputs
func (t *TransactionDataV0) CoinOutputs() []CoinOutput {
	return t.coinOutputs
}

// BlockStakeInputs implements TransactionData.BlockStakeInputs
func (t *TransactionDataV0) BlockStakeInputs() []BlockStakeInput {
	return t.blockStakeInputs
}

// BlockStakeOutputs implements TransactionData.BlockStakeOutputs
func (t *TransactionDataV0) BlockStakeOutputs() []BlockStakeOutput {
	return t.blockStakeOutputs
}

// MinerFees implements TransactionData.MinerFees
func (t *TransactionDataV0) MinerFees() []Currency {
	return t.minerFees
}

// ArbitraryData implements TransactionData.ArbitraryData
func (t *TransactionDataV0) ArbitraryData() []byte {
	return t.arbitraryData
}

// ValidateTransaction implements TransactionData.ValidateTransaction
func (t *TransactionDataV0) ValidateTransaction(ctx TransactionValidationContext) (err error) {
	err = TransactionFitsInABlock(t, ctx.BlockSizeLimit)
	if err != nil {
		return
	}

	err = NoDoubleCoinSpend(t.coinInputs)
	if err != nil {
		return
	}
	err = NoDoubleBlockStakeSpend(t.blockStakeInputs)
	if err != nil {
		return
	}

	err = NoZeroCoinOutputs(t.coinOutputs)
	if err != nil {
		return
	}
	err = NoZeroBlockStakeOutputs(t.blockStakeOutputs)
	if err != nil {
		return
	}
	err = NoZeroOutputCurrency(t.minerFees)
	if err != nil {
		return
	}

	return ValidTransactionSignatures(t, ctx.BlockHeight)
}

// InputSigHash implements TransactionData.InputSigHash
func (t *TransactionDataV0) InputSigHash(inputIndex uint64, extraObjects ...interface{}) (hash crypto.Hash) {
	h := crypto.NewHash()
	enc := encoding.NewEncoder(h)

	enc.Encode(inputIndex)
	if len(extraObjects) > 0 {
		enc.EncodeAll(extraObjects...)
	}
	for _, ci := range t.coinInputs {
		enc.EncodeAll(ci.ParentID, ci.Unlocker.UnlockHash())
	}
	enc.Encode(t.coinOutputs)
	for _, bsi := range t.blockStakeInputs {
		enc.EncodeAll(bsi.ParentID, bsi.Unlocker.UnlockHash())
	}
	enc.EncodeAll(
		t.blockStakeOutputs,
		t.minerFees,
		t.arbitraryData,
	)

	h.Sum(hash[:0])
	return
}

// MarshalSia implements TransactionData.SiaMarshaler.MarshalSia
func (t *TransactionDataV0) MarshalSia(w io.Writer) error {
	return encoding.NewEncoder(w).EncodeAll(
		t.coinInputs,
		t.coinOutputs,
		t.blockStakeInputs,
		t.blockStakeOutputs,
		t.minerFees,
		t.arbitraryData,
	)
}

// UnmarshalSia implements TransactionData.SiaUnmarshaler.UnmarshalSia
func (t *TransactionDataV0) UnmarshalSia(r io.Reader) error {
	return encoding.NewDecoder(r).DecodeAll(
		&t.coinInputs,
		&t.coinOutputs,
		&t.blockStakeInputs,
		&t.blockStakeOutputs,
		&t.minerFees,
		&t.arbitraryData,
	)
}

var (
	_ encoding.SiaMarshaler   = (*TransactionDataV0)(nil)
	_ encoding.SiaUnmarshaler = (*TransactionDataV0)(nil)
)

type jsonTransactionV0 struct {
	CoinInputs        []CoinInput        `json:"coininputs"`
	CoinOutputs       []CoinOutput       `json:"coinoutputs,omitempty"`
	BlockstakeInputs  []BlockStakeInput  `json:"blockstakeinputs,omitempty"`
	BlockStakeOutputs []BlockStakeOutput `json:"blockstakeoutputs,omitempty"`
	MinerFees         []Currency         `json:"minerfees"`
	ArbitraryData     []byte             `json:"arbitrarydata,omitempty"`
}

// MarshalJSON implements TransactionData.JSONMarshaler.MarshalJSON
func (t *TransactionDataV0) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonTransactionV0{
		CoinInputs:        t.coinInputs,
		CoinOutputs:       t.coinOutputs,
		BlockstakeInputs:  t.blockStakeInputs,
		BlockStakeOutputs: t.blockStakeOutputs,
		MinerFees:         t.minerFees,
		ArbitraryData:     t.arbitraryData,
	})
}

// UnmarshalJSON implements TransactionData.JSONUnmarshaler.UnmarshalJSON
func (t *TransactionDataV0) UnmarshalJSON(b []byte) error {
	var data jsonTransactionV0
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}
	t.coinInputs = data.CoinInputs
	t.coinOutputs = data.CoinOutputs
	t.blockStakeInputs = data.BlockstakeInputs
	t.blockStakeOutputs = data.BlockStakeOutputs
	t.minerFees = data.MinerFees
	t.arbitraryData = data.ArbitraryData
	return nil
}

var (
	_ json.Marshaler   = (*TransactionDataV0)(nil)
	_ json.Unmarshaler = (*TransactionDataV0)(nil)
)
