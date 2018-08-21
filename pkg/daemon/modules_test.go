package daemon

import (
	"bytes"
	"testing"
)

func TestDefaultModuleSetFlag(t *testing.T) {
	// create the default flag
	flag := DefaultModuleSetFlag()

	// test that the default str is used
	str, expectedStr := flag.String(), "cgtwb"
	if expectedStr != str {
		t.Fatal("unexpected flag string:", expectedStr, "!=", str)
	}

	// set flag as a pure explorer node might do
	err := flag.Set("gce")
	if err != nil {
		t.Fatal("failed to set module flag set as a pure explorer node might do:", err)
	}
	str, expectedStr = flag.String(), "gce"
	if expectedStr != str {
		t.Fatal("unexpected flag string:", expectedStr, "!=", str)
	}

	// set flag as a complete explorer node might do
	err = flag.Set("gcet")
	if err != nil {
		t.Fatal("failed to set module flag set as a complete explorer node might do:", err)
	}
	str, expectedStr = flag.String(), "gcet"
	if expectedStr != str {
		t.Fatal("unexpected flag string:", expectedStr, "!=", str)
	}

	// set flag as a non-block-creating non-explorer-enabled full node might do
	err = flag.Set("gctw")
	if err != nil {
		t.Fatal("failed to set module flag set as a complete explorer node might do:", err)
	}
	str, expectedStr = flag.String(), "gctw"
	if expectedStr != str {
		t.Fatal("unexpected flag string:", expectedStr, "!=", str)
	}

	buffer := bytes.NewBuffer(nil)
	err = flag.WriteDescription(buffer)
	if err != nil {
		t.Fatal("failed to write full description:", err)
	}
	bs := buffer.Bytes()
	// description should be non-nil, and the function shouldn't panic,
	//  but beyond that we won't test it
	if len(bs) == 0 {
		t.Fatal("empty full description returned")
	}
}

func TestModuleMethodIdentifier(t *testing.T) {
	testCases := []struct {
		Module             *Module
		ExpectedIdentifier ModuleIdentifier
	}{
		{GatewayModule, 'g'},
		{ConsensusSetModule, 'c'},
		{TransactionPoolModule, 't'},
		{WalletModule, 'w'},
		{BlockCreatorModule, 'b'},
		{ExplorerModule, 'e'},
	}
	for idx, testCase := range testCases {
		identifier := testCase.Module.Identifier()
		if identifier != testCase.ExpectedIdentifier {
			t.Error(idx, testCase.Module.Name, ":", string(identifier), "!=", string(testCase.ExpectedIdentifier))
		}
	}
}

func TestDefaultModuleIdentifiers(t *testing.T) {
	set := DefaultModuleSet()
	expectedIdentifiers := []ModuleIdentifier{'g', 'c', 't', 'w', 'b', 'e'}
	if len(set.modules) != len(expectedIdentifiers) {
		t.Fatal("unexpected length for default module set: ", len(set.modules), "!=", len(expectedIdentifiers))
	}
	for idx, mod := range set.modules {
		if id := mod.Identifier(); id != expectedIdentifiers[idx] {
			t.Error("unxpected modifier at position", idx, ":", string(id), string(expectedIdentifiers[idx]))
		}
	}
}

func TestModuleSetMethodCreateDependencySetFor(t *testing.T) {
	set := DefaultModuleSet()
	testCases := []struct {
		Identifier           ModuleIdentifier
		ExpectedDependencies ModuleIdentifierSet
	}{
		{'g', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'g'}}},
		{'c', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'c', 'g'}}},
		{'t', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'t', 'c', 'g'}}},
		{'w', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'w', 'c', 'g', 't'}}},
		{'b', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'b', 'c', 'g', 't', 'w'}}},
		{'e', ModuleIdentifierSet{identifiers: []ModuleIdentifier{'e', 'c', 'g'}}},
	}
	for idx, testCase := range testCases {
		dependencies, err := set.CreateDependencySetFor(testCase.Identifier)
		if err != nil {
			t.Error(idx, "failed to create dependency set for", string(testCase.Identifier), ":", err)
			continue
		}
		depStr := dependencies.String()
		expectedDepSr := testCase.ExpectedDependencies.String()
		if depStr != expectedDepSr {
			t.Error(idx, "unexpected dependency set for identifier", string(testCase.Identifier), ":", depStr, "!=", expectedDepSr)
		}
	}
	// create a dep set will all test cases,
	// should simply equal the given testCases
	var (
		depSet         ModuleIdentifierSet
		expectedDepSet ModuleIdentifierSet
	)
	for idx, testCase := range testCases {
		err := expectedDepSet.Append(testCase.Identifier)
		if err != nil {
			t.Fatal(idx, "failed to append identifier", string(testCase.Identifier))
		}
		err = set.createDependencySetFor(testCase.Identifier, &depSet)
		if err != nil {
			t.Fatal(idx, "failed to create dependency set for identifier", string(testCase.Identifier))
		}
	}
	depStr := depSet.String()
	expectedDepSr := expectedDepSet.String()
	if depStr != expectedDepSr {
		t.Error("unexpected dependency set for all testcase identifiers:", depStr, "!=", expectedDepSr)
	}
}

func TestModuleSetMethodCreateDependencySetForWithCoDependency(t *testing.T) {
	set, err := NewModuleSet(
		&Module{Name: "A", Description: "module a", Dependencies: ForceNewIdentifierSet('b')},
		&Module{Name: "B", Description: "module b", Dependencies: ForceNewIdentifierSet('c', 'a')},
		&Module{Name: "C", Description: "module c", Dependencies: ForceNewIdentifierSet('a')},
	)
	if err != nil {
		t.Fatal("failed to create co-dependend module set", err)
	}
	const expectedDepStr = "abc"
	var dependencies ModuleIdentifierSet
	for idx, mod := range set.modules {
		err = set.createDependencySetFor(mod.Identifier(), &dependencies)
		if err != nil {
			t.Fatalf("%d, failed to create dependency set for id %s", idx, string(mod.Identifier()))
		}
	}
	depStr := dependencies.String()
	if expectedDepStr != depStr {
		t.Fatal("unexpected dependency set:", expectedDepStr, "!=", depStr)
	}
}

func TestModuleIdentifierSet(t *testing.T) {
	var set ModuleIdentifierSet
	str, expectedStr := set.String(), ""
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appending 'a' to an empty set should be OK
	err := set.Append('a')
	if err != nil {
		t.Fatal("append of 'a' should be OK, but it failed: ", err)
	}
	str, expectedStr = set.String(), "a"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appending 'a' to a set which already contains 'a' should fail
	err = set.Append('a')
	if err == nil {
		t.Error("append of 'a' shouldn't be OK, but it didn't fail: ", err)
	}
	str, expectedStr = set.String(), "a"
	if expectedStr != str { // set should be left untouched
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appending 'b' to a set which doesn't contain 'b' yetshould be OK
	err = set.Append('b')
	if err != nil {
		t.Fatal("append of 'b' should be OK, but it failed: ", err)
	}
	str, expectedStr = set.String(), "ab"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appendIfUnique will return false, but no error, when attempting to append a duplicate
	unique, err := set.AppendIfUnique('b')
	if err != nil {
		t.Error("AppendIfUnique of 'b' should be OK, but it failed: ", err)
	}
	if unique {
		t.Error("AppendIfUnique of 'b' should return false, given 'b' already exists, but it didn't")
	}
	str, expectedStr = set.String(), "ab"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appendIfUnique will return true, but no error, when attempting to append a duplicate
	unique, err = set.AppendIfUnique('c')
	if err != nil {
		t.Error("AppendIfUnique of 'c' should be OK, but it failed: ", err)
	}
	if !unique {
		t.Error("AppendIfUnique of 'c' should return true, given 'c' doesn't exist yet, but it didn't")
	}
	str, expectedStr = set.String(), "abc"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
}

func TestModuleSet(t *testing.T) {
	var set ModuleSet
	// the empty module set should return an empty string
	str, expectedStr := set.String(), ""
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// append a unique module A
	err := set.Append(&Module{Name: "A", Description: "a original"})
	if err != nil {
		t.Fatal("failed to append a unique module to an empty set:", err)
	}
	str, expectedStr = set.String(), "a"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// appending module A should fail
	err = set.Append(&Module{Name: "A", Description: "a modified"})
	if err == nil {
		t.Fatal("managed to append non-unique element to a set")
	}
	str, expectedStr = set.String(), "a"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	description, expectedDescription := set.moduleForIdentifier('a').Description, "a original"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'a':", expectedDescription, "!=", description)
	}
	// append a unique module B
	err = set.Append(&Module{Name: "B", Description: "b original"})
	if err != nil {
		t.Fatal("failed to append a unique module to a non-empty set:", err)
	}
	str, expectedStr = set.String(), "ab"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// setting module A (overwriting it) should work
	set.Set(&Module{Name: "AB", Description: "a modified"})
	str, expectedStr = set.String(), "ab"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	description, expectedDescription = set.moduleForIdentifier('a').Description, "a modified"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'a' after overwriting 'a':", expectedDescription, "!=", description)
	}
	description, expectedDescription = set.moduleForIdentifier('b').Description, "b original"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'b' after overwriting 'a':", expectedDescription, "!=", description)
	}

	// setting module C (creating it as new) should work as well
	set.Set(&Module{Name: "C", Description: "c original"})
	str, expectedStr = set.String(), "abc"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	description, expectedDescription = set.moduleForIdentifier('c').Description, "c original"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'c' after creating 'c':", expectedDescription, "!=", description)
	}
	description, expectedDescription = set.moduleForIdentifier('a').Description, "a modified"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'a' after creating 'c':", expectedDescription, "!=", description)
	}
	description, expectedDescription = set.moduleForIdentifier('b').Description, "b original"
	if expectedDescription != description {
		t.Fatal("unexpected module description for 'b' after creating 'c':", expectedDescription, "!=", description)
	}
}

func TestNewModuleIdentifierSet(t *testing.T) {
	// test invalid cases
	_, err := NewIdentifierSet()
	if err == nil {
		t.Error("should fail as no identifiers were given, but it didn't fail")
	}
	_, err = NewIdentifierSet('a', 'a')
	if err == nil {
		t.Error("should fail as duplicate identifiers were given, but it didn't fail: {a, a}")
	}
	_, err = NewIdentifierSet('a', 'b', 'a')
	if err == nil {
		t.Error("should fail as duplicate identifiers were given, but it didn't fail: {a, b, a}")
	}
	_, err = NewIdentifierSet('a', 'b', 'c', 'a')
	if err == nil {
		t.Error("should fail as duplicate identifiers were given, but it didn't fail: {a, b, c, a}")
	}
	// test a valid case
	set, err := NewIdentifierSet('a', 'b', 'c', 'd', 'e')
	if err != nil {
		t.Fatal("should be possible to create an identifier set of unique identifiers but it failed:", err)
	}
	str, expectedStr := set.String(), "abcde"
	if expectedStr != str {
		t.Fatal("unexpected set string:", expectedStr, "!=", str)
	}
	// ensure that the returned identifier slice is a clone
	identifiers := set.Identifiers()
	identifiers[0] = 'z'
	str, expectedStr = set.String(), "abcde"
	if expectedStr != str {
		t.Fatal("unexpected set string (after modification of returned identifiers):", expectedStr, "!=", str)
	}
	// sanity check for previous test
	set.identifiers[0] = 'z'
	str, expectedStr = set.String(), "zbcde"
	if expectedStr != str {
		t.Fatal("unexpected set string (after modification of internal identifiers):", expectedStr, "!=", str)
	}
}

func TestIsValidModuleIdentifier(t *testing.T) {
	for i := 0x61; i <= 0x7A; i++ {
		if !IsValidModuleIdentifier(ModuleIdentifier(i)) {
			t.Errorf("%s is a valid module identifier, yet it is not considered as such", string(i))
		}
	}
}
