package types

import (
	"errors"

	"github.com/rivine/rivine/encoding"
)

// Errors returned for invalid transactions.
var (
	ErrDoubleSpend         = errors.New("transaction uses a parent object twice")
	ErrTransactionTooLarge = errors.New("transaction is too large to fit in a block")
	ErrZeroOutput          = errors.New("transaction cannot have an output or payout that has zero value")
)

// TransactionFitsInABlock checks if the transaction is likely to fit in a block.
// Currently there is no limitation on transaction size other than it must fit
// in a block.
func TransactionFitsInABlock(t TransactionData, blockSizeLimit uint64) error {
	// Check that the transaction will fit inside of a block, leaving 5kb for
	// overhead.
	if uint64(len(encoding.Marshal(t))) > blockSizeLimit-5e3 {
		return ErrTransactionTooLarge
	}
	return nil
}

// NoZeroCoinOutputs ensures no coin output has a zero value.
func NoZeroCoinOutputs(cos []CoinOutput) error {
	for _, co := range cos {
		if co.Value.IsZero() {
			return ErrZeroOutput
		}
	}
	return nil
}

// NoZeroBlockStakeOutputs ensures no coin output has a zero value.
func NoZeroBlockStakeOutputs(bsos []BlockStakeOutput) error {
	for _, bso := range bsos {
		if bso.Value.IsZero() {
			return ErrZeroOutput
		}
	}
	return nil
}

// NoZeroOutputCurrency ensures no output currency has a zero value.
func NoZeroOutputCurrency(cs []Currency) error {
	for _, c := range cs {
		if c.IsZero() {
			return ErrZeroOutput
		}
	}
	return nil
}

func NoDoubleCoinSpend(cis []CoinInput) error {
	// Check that there are no repeat instances of coin outputs
	var (
		exists     bool
		coinInputs = make(map[CoinOutputID]struct{})
	)
	for _, ci := range cis {
		_, exists = coinInputs[ci.ParentID]
		if exists {
			return ErrDoubleSpend
		}
		coinInputs[ci.ParentID] = struct{}{}
	}
	return nil
}

func NoDoubleBlockStakeSpend(bsis []BlockStakeInput) error {
	// Check that there are no repeat instances of block stake outputs
	var (
		exists            bool
		blockStakesInputs = make(map[BlockStakeOutputID]struct{})
	)
	for _, bsi := range bsis {
		_, exists = blockStakesInputs[bsi.ParentID]
		if exists {
			return ErrDoubleSpend
		}
		blockStakesInputs[bsi.ParentID] = struct{}{}
	}
	return nil
}

// ValidTransactionSignatures checks the validaty of all signatures in a transaction.
func ValidTransactionSignatures(t TransactionData, currentHeight BlockHeight) (err error) {
	spendCoins := make(map[CoinOutputID]struct{})
	for index, ci := range t.CoinInputs() {
		if _, found := spendCoins[ci.ParentID]; found {
			err = ErrDoubleSpend
			return
		}
		spendCoins[ci.ParentID] = struct{}{}
		err = ci.Unlocker.Unlock(uint64(index), t)
		if err != nil {
			return
		}
	}

	spendBlockStakes := make(map[BlockStakeOutputID]struct{})
	for index, bsi := range t.BlockStakeInputs() {
		if _, found := spendBlockStakes[bsi.ParentID]; found {
			err = ErrDoubleSpend
			return
		}
		spendBlockStakes[bsi.ParentID] = struct{}{}
		err = bsi.Unlocker.Unlock(uint64(index), t)
		if err != nil {
			return
		}
	}

	return
}
