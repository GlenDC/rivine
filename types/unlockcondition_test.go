package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rivine/rivine/crypto"
	"github.com/rivine/rivine/encoding"
)

func TestUnlockConditionSiaEncoding(t *testing.T) {
	testCases := []string{
		// nil condition
		`000000000000000000`,
		// unknown condition
		`ff0c0000000000000048656c6c6f2c205465737421`,
		// unlock hash condition
		`012100000000000000016363636363636363636363636363636363636363636363636363636363636363`,
		// atomic swap condition
		`026a0000000000000001454545454545454545454545454545454545454545454545454545454545454501636363636363636363636363636363636363636363636363636363636363636378787878787878787878787878787878787878787878787878787878787878781234567812345678`,
	}
	for idx, testCase := range testCases {
		b, err := hex.DecodeString(testCase)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		var up UnlockConditionProxy
		err = up.UnmarshalSia(bytes.NewReader(b))
		if err != nil {
			t.Error(idx, err)
			continue
		}

		buf := bytes.NewBuffer(nil)
		err = up.MarshalSia(buf)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		out := hex.EncodeToString(buf.Bytes())
		if out != testCase {
			t.Error(idx, out, "!=", testCase)
		}
	}
}

func TestUnlockFulfillmentSiaEncoding(t *testing.T) {
	testCases := []string{
		// nil fulfillment
		`000000000000000000`,
		// unknown fulfillment
		`ff0c0000000000000048656c6c6f2c205465737421`,
		// single signature fulfillment
		`01800000000000000065643235353139000000000000000000200000000000000035fffffffffffffffffffffffffffffffffffffffffffffffff46fffffffffff4000000000000000fffffffffffffffffffffffffffff123ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`,
		// legacy atomic swap fulfillment
		`020a01000000000000011234567891234567891234567891234567891234567891234567891234567891016363636363636363636363636363636363636363636363636363636363636363bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb07edb85a00000000656432353531390000000000000000002000000000000000abababababababababababababababababababababababababababababababab4000000000000000dededededededededededededededededededededededededededededededededededededededededededededededededededededededededededededededededabadabadabadabadabadabadabadabadabadabadabadabadabadabadabadaba`,
		// atomic swap fulfillment
		`02a000000000000000656432353531390000000000000000002000000000000000fffffffffffffffffffffffffffffffff04fffffffffffffffffffffffffffff4000000000000000ffffffffffffffffffffffff56fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff2ffffffffffffffffff123ffffffffffafffffffffffeffffffffffffff`,
	}
	for idx, testCase := range testCases {
		b, err := hex.DecodeString(testCase)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		var uf UnlockFulfillmentProxy
		err = uf.UnmarshalSia(bytes.NewReader(b))
		if err != nil {
			t.Error(idx, err)
			continue
		}

		buf := bytes.NewBuffer(nil)
		err = uf.MarshalSia(buf)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		out := hex.EncodeToString(buf.Bytes())
		if out != testCase {
			t.Error(idx, out, "!=", testCase)
		}
	}
}

func TestUnlockConditionJSONEncoding(t *testing.T) {
	testCases := []struct {
		Input  string
		Output string
	}{
		// nil condition
		{`{}`, ``},
		{`{"type":0}`, `{}`},
		{`{"type":0,"data":null}`, `{}`},
		// unlock hash condition
		{`{
	"type":1,
	"data":{ 
		"unlockhash":"01a6a6c5584b2bfbd08738996cd7930831f958b9a5ed1595525236e861c1a0dc353bdcf54be7d8"
	}
}`, ``},
		{`{
	"type":1,
	"data": {
		"unlockhash":"6453402d094ed0f336950c4be0feec37167aaaaf8b974d265900e49ab22773584cfe96393b1360"
	}
}`, ``},
		{`{
	"type": 1,
	"data": {
		"unlockhash": "0101234567890123456789012345678901012345678901234567890123456789018a50e31447b8"
	}
}`, ``},
		// atomic swap condition
		{`{
	"type": 2,
	"data": {
		"sender": "6453402d094ed0f336950c4be0feec37167aaaaf8b974d265900e49ab22773584cfe96393b1360",
		"receiver": "0101234567890123456789012345678901012345678901234567890123456789018a50e31447b8",
		"hashedsecret": "abc543defabc543defabc543defabc543defabc543defabc543defabc543defa",
		"timelock": 1522068743
	}
}`, ``},
	}
	for idx, testCase := range testCases {
		var up UnlockConditionProxy
		err := json.Unmarshal([]byte(testCase.Input), &up)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		b, err := json.Marshal(up)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		expected := testCase.Output
		if expected == "" {
			expected = testCase.Input
		}
		expected = strings.Replace(strings.Replace(strings.Replace(
			expected, " ", "", -1), "\t", "", -1), "\n", "", -1)
		out := string(b)
		if out != expected {
			t.Error(idx, out, "!=", expected)
		}
	}
}

func TestUnlockFulfillmentJSONEncoding(t *testing.T) {
	testCases := []struct {
		Input  string
		Output string
	}{
		// nil fulfillment
		{`{}`, ``},
		{`{"type":0}`, `{}`},
		{`{"type":0,"data":null}`, `{}`},
		// single signature fulfillment
		{`{
	"type": 1,
	"data": {
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab"
	}
}`, ``},
		// legacy atomic swap fulfillment
		{
			`{
	"type": 2,
	"data": {
		"sender": "6453402d094ed0f336950c4be0feec37167aaaaf8b974d265900e49ab22773584cfe96393b1360",
		"receiver": "0101234567890123456789012345678901012345678901234567890123456789018a50e31447b8",
		"hashedsecret": "abc543defabc543defabc543defabc543defabc543defabc543defabc543defa",
		"timelock": 1522068743,
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab"
	}
}`, `{
	"type": 2,
	"data": {
		"sender": "6453402d094ed0f336950c4be0feec37167aaaaf8b974d265900e49ab22773584cfe96393b1360",
		"receiver": "0101234567890123456789012345678901012345678901234567890123456789018a50e31447b8",
		"hashedsecret": "abc543defabc543defabc543defabc543defabc543defabc543defabc543defa",
		"timelock": 1522068743,
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab",
		"secret": "0000000000000000000000000000000000000000000000000000000000000000"
	}
}`},
		{
			`{
	"type": 2,
	"data": {
		"sender": "6453402d094ed0f336950c4be0feec37167aaaaf8b974d265900e49ab22773584cfe96393b1360",
		"receiver": "0101234567890123456789012345678901012345678901234567890123456789018a50e31447b8",
		"hashedsecret": "abc543defabc543defabc543defabc543defabc543defabc543defabc543defa",
		"timelock": 1522068743,
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab",
		"secret": "def789def789def789def789def789dedef789def789def789def789def789de"
	}
}`, ``},
		// atomic swap fulfillment
		{
			`{
	"type": 2,
	"data": {
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab"
	}
}`, `{
	"type": 2,
	"data": {
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab",
		"secret": "0000000000000000000000000000000000000000000000000000000000000000"
	}
}`},
		{
			`{
	"type": 2,
	"data": {
		"publickey": "ed25519:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
		"signature": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab",
		"secret": "def789def789def789def789def789dedef789def789def789def789def789de"
	}
}`, ``},
	}
	for idx, testCase := range testCases {
		var fp UnlockFulfillmentProxy
		err := json.Unmarshal([]byte(testCase.Input), &fp)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		b, err := json.Marshal(fp)
		if err != nil {
			t.Error(idx, err)
			continue
		}

		expected := testCase.Output
		if expected == "" {
			expected = testCase.Input
		}
		expected = strings.Replace(strings.Replace(strings.Replace(
			expected, " ", "", -1), "\t", "", -1), "\n", "", -1)
		out := string(b)
		if out != expected {
			t.Error(idx, out, "!=", expected)
		}
	}
}

func TestNilUnlockConditionProxy(t *testing.T) {
	var c UnlockConditionProxy
	if ct := c.ConditionType(); ct != ConditionTypeNil {
		t.Error("ConditionType", ct, "!=", ConditionTypeNil)
	}
	if err := c.IsStandardCondition(); err != nil {
		t.Error("IsStandardCondition", err)
	}
	if b, err := c.MarshalJSON(); err != nil || string(b) != "{}" {
		t.Error("MarshalJSON", b, err)
	}
	if b := encoding.Marshal(c); bytes.Compare(b, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0}) != 0 {
		t.Error("MarshalSia", b)
	}
}

func TestUnlockConditionEqual(t *testing.T) {
	// TODO
}

func TestUnlockFulfillmentEqual(t *testing.T) {
	// TODO
}

func TestFulfillLegacyCompatibility(t *testing.T) {
	// utility funcs
	hbs := func(str string) []byte { // hexStr -> byte slice
		bs, _ := hex.DecodeString(str)
		return bs
	}
	hs := func(str string) (hash crypto.Hash) { // hbs -> crypto.Hash
		copy(hash[:], hbs(str))
		return
	}

	testCases := []struct {
		Transaction                      Transaction
		CoinConditions                   []UnlockCondition
		ExpectedCoinIdentifiers          []CoinOutputID
		ExpectedCoinInputSigHashes       []ByteSlice
		BlockStakeConditions             []UnlockCondition
		ExpectedBlockStakeIdentifiers    []BlockStakeOutputID
		ExpectedBlockStakeInputSigHashes []ByteSlice
		ExpectedTransactionIdentifier    TransactionID
	}{
		{
			Transaction{
				Version: TransactionVersionZero,
				BlockStakeInputs: []BlockStakeInput{
					{
						ParentID: BlockStakeOutputID(hs("a4292b24a9868649efa7ec49221b97043554eefb4be92de8d6ac885c2fa533c4")),
						Fulfillment: UnlockFulfillmentProxy{
							Fulfillment: &SingleSignatureFulfillment{
								PublicKey: SiaPublicKey{
									Algorithm: SignatureEd25519,
									Key:       hbs("8d368f6c457f1f7f49f4cb32636c1d34197c046f5398ea6661b0b4ecfe36a3cd"),
								},
								Signature: hbs("248fce862f030e5e98962b43cb437a809aa30ba99367db018e410c8a6854be88a03c07c9f788fe75d0f12af9ddc39f9c9508aa55283a6ac02c41e8cc7be8f303"),
							},
						},
					},
				},
				BlockStakeOutputs: []BlockStakeOutput{
					{
						Value: NewCurrency64(400),
						Condition: UnlockConditionProxy{
							Condition: &UnlockHashCondition{
								TargetUnlockHash: unlockHashFromHex("01746677df456546d93729066dd88514e2009930f3eebac3c93d43c88a108f8f9aa9e7c6f58893"),
							},
						},
					},
				},
			},
			nil,
			nil,
			nil,
			[]UnlockCondition{
				&UnlockHashCondition{
					TargetUnlockHash: unlockHashFromHex("01746677df456546d93729066dd88514e2009930f3eebac3c93d43c88a108f8f9aa9e7c6f58893"),
				},
			},
			[]BlockStakeOutputID{
				BlockStakeOutputID(hs("03ee547f5efbc60cef3f185471a532faa284f3ec3900da8a929525ba459708d5")),
			},
			[]ByteSlice{
				hbs("798144cd1e876daf6f0d5008547dbda8ae69ef3b7dd94555d7c14e6e5ccdeeda"),
			},
			TransactionID(hs("6255ff840923595598a134795a66814e512395f5c9e96669e7f2c104c98ff090")),
		},
		{
			Transaction{
				Version: TransactionVersionZero,
				CoinInputs: []CoinInput{
					{
						ParentID: CoinOutputID(hs("9a3b7ea912f6438eec826b49b71876e92b09624621a51c8f1ca76645a54cab4a")),
						Fulfillment: UnlockFulfillmentProxy{
							Fulfillment: &SingleSignatureFulfillment{
								PublicKey: SiaPublicKey{
									Algorithm: SignatureEd25519,
									Key:       hbs("07fa00de51b678926885e96fb1904d3eebca2c283dee40e975871ed6109f7f4b"),
								},
								Signature: hbs("ae8e2891033e260bf35f7c340823818a46cb6240aac8aa4bcdadecf30604b54d339ec9930b8be95a9a779bb48027e6314d8b2f701809cd352b1d14753a145f01"),
							},
						},
					},
				},
				CoinOutputs: []CoinOutput{
					{
						Value: NewCurrency64(100000000000),
						Condition: UnlockConditionProxy{
							Condition: &UnlockHashCondition{
								TargetUnlockHash: unlockHashFromHex("015fe50b9c596d8717e5e7ba79d5a7c9c8b82b1427a04d5c0771268197c90e99dccbcdf0ba9c90"),
							},
						},
					},
					{
						Value: NewCurrency64(694999899800000000),
						Condition: UnlockConditionProxy{
							Condition: &UnlockHashCondition{
								TargetUnlockHash: unlockHashFromHex("01d3a8d366864f5f368bd73959139c55da5f1f8beaa07cb43519cc87d2a51135ae0b3ba93cf2d9"),
							},
						},
					},
				},
				MinerFees: []Currency{
					NewCurrency64(100000000),
				},
			},
			[]UnlockCondition{
				&UnlockHashCondition{
					TargetUnlockHash: unlockHashFromHex("01437c56286c76dec14e87f5da5e5a436651006e6cd46bee5865c9060ba178f7296ed843b70a57"),
				},
			},
			[]CoinOutputID{
				CoinOutputID(hs("8c193a699d27799efebb52e501ed7fdbc4da38a3cf539c431e9659734e23827d")),
				CoinOutputID(hs("2829711c7dd071d3d3031d30eedbae3d126d62d3ac3369b01cecdda7d2aebfef")),
			},
			[]ByteSlice{
				hbs("b6847f66a5437ef11250eebd0eccb7454dca395e1de68a6f7f86f3c5014a238d"),
			},
			nil,
			nil,
			nil,
			TransactionID(hs("f6f7c6bd071ea9403d07a74c865e5aa2074564cd557e81746a945695c0dcf579")),
		},
	}
	for tidx, testCase := range testCases {
		for idx, ci := range testCase.Transaction.CoinInputs {
			sigHash := testCase.Transaction.InputSigHash(uint64(idx))
			if bytes.Compare(testCase.ExpectedCoinInputSigHashes[idx][:], sigHash[:]) != 0 {
				t.Error(tidx, idx, "invalid coin input sigh hash",
					testCase.ExpectedCoinInputSigHashes[idx], "!=", sigHash)
			}

			err := ci.Fulfillment.IsStandardFulfillment()
			if err != nil {
				t.Error(tidx, idx, "unexpected error", err)
			}

			err = ci.Fulfillment.Fulfill(testCase.CoinConditions[idx], FulfillContext{
				InputIndex:  uint64(idx),
				Transaction: testCase.Transaction,
			})
			if err != nil {
				t.Error(tidx, idx, err)
			}
		}
		for idx, bsi := range testCase.Transaction.BlockStakeInputs {
			sigHash := testCase.Transaction.InputSigHash(uint64(idx))
			if bytes.Compare(testCase.ExpectedBlockStakeInputSigHashes[idx][:], sigHash[:]) != 0 {
				t.Error(tidx, idx, "invalid bs input sigh hash",
					testCase.ExpectedBlockStakeInputSigHashes[idx], "!=", sigHash)
			}

			err := bsi.Fulfillment.IsStandardFulfillment()
			if err != nil {
				t.Error(tidx, idx, "unexpected error", err)
			}

			err = bsi.Fulfillment.Fulfill(testCase.BlockStakeConditions[idx], FulfillContext{
				InputIndex:  uint64(idx),
				Transaction: testCase.Transaction,
			})
			if err != nil {
				t.Error(tidx, idx, err)
			}
		}
		for idx, co := range testCase.Transaction.CoinOutputs {
			outputID := testCase.Transaction.CoinOutputID(uint64(idx))
			if bytes.Compare(testCase.ExpectedCoinIdentifiers[idx][:], outputID[:]) != 0 {
				t.Error(tidx, idx, testCase.ExpectedCoinIdentifiers[idx], "!=", outputID)
			}

			err := co.Condition.IsStandardCondition()
			if err != nil {
				t.Error(tidx, idx, "unexpected error", err)
			}
		}
		for idx, bso := range testCase.Transaction.BlockStakeOutputs {
			outputID := testCase.Transaction.BlockStakeOutputID(uint64(idx))
			if bytes.Compare(testCase.ExpectedBlockStakeIdentifiers[idx][:], outputID[:]) != 0 {
				t.Error(tidx, idx, testCase.ExpectedBlockStakeIdentifiers[idx], "!=", outputID)
			}

			err := bso.Condition.IsStandardCondition()
			if err != nil {
				t.Error(tidx, idx, "unexpected error", err)
			}
		}
		transactionID := testCase.Transaction.ID()
		if bytes.Compare(testCase.ExpectedTransactionIdentifier[:], transactionID[:]) != 0 {
			t.Error(tidx, testCase.ExpectedTransactionIdentifier, "!=", transactionID)
		}
	}
}

func TestIsStandardCondition(t *testing.T) {
	// TODO
}

func TestIsStandardFulfillment(t *testing.T) {
	// TODO
}
