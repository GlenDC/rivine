package types

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

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

func TestEqual(t *testing.T) {
	// TODO
}

func TestFulfill(t *testing.T) {
	// TODO
}

func TestIsStandardCondition(t *testing.T) {
	// TODO
}

func TestIsStandardFulfillment(t *testing.T) {
	// TODO
}
