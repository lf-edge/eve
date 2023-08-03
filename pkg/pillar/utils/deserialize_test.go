package utils

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

type TestStruct struct {
	Field1 string `mandatory:"true"`
	Field2 int
}

func TestDeserializeToStruct(t *testing.T) {
	testSimpleStruct(t)
	testErrorConditions(t)
	testMandatoryFieldLogic(t)
	testExtraFieldInFile(t)
	testMissingNonMandatoryFieldInFile(t)
	testStructWithAnonymousField(t)
	testNestedStructs(t)
	testArrayOfStructs(t)
	testAnonymousStructs(t)
}

func testSimpleStruct(t *testing.T) {
	t.Log("Testing simple struct...")
	tmpfile, testObject := createTempFileWithObject(t, TestStruct{
		Field1: "test",
		Field2: 123,
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStruct
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
	if result != testObject {
		t.Errorf("expected %v, got %v", testObject, result)
	} else {
		t.Log("Success: simple struct")
	}
}

func testErrorConditions(t *testing.T) {
	t.Log("Testing error conditions...")
	var result TestStruct
	err := DeserializeToStruct("nonexistentfile", &result)
	if err == nil {
		t.Errorf("expected error, got nil")
	} else {
		t.Log("Success: nonexistent file")
	}
	err = DeserializeToStruct("", result) // not a pointer
	if err == nil {
		t.Errorf("expected error, got nil")
	} else {
		t.Log("Success: non-pointer argument")
	}
	err = DeserializeToStruct("", &[]TestStruct{}) // not a struct
	if err == nil {
		t.Errorf("expected error, got nil")
	} else {
		t.Log("Success: non-struct argument")
	}
}

func testMandatoryFieldLogic(t *testing.T) {
	t.Log("Testing mandatory field logic...")
	tmpfile, _ := createTempFileWithObject(t, struct {
		Field2 int
	}{
		Field2: 123,
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStruct
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err == nil {
		t.Errorf("expected error due to missing mandatory field, got nil")
	} else {
		t.Log("Success: missing mandatory field")
	}
}

func testExtraFieldInFile(t *testing.T) {
	t.Log("Testing extra field in file...")
	tmpfile, _ := createTempFileWithObject(t, struct {
		Field1 string `mandatory:"true"`
		Field2 int
		Field3 string
	}{
		Field1: "test",
		Field2: 123,
		Field3: "extra",
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStruct
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: extra field in file")
	}
}

func testMissingNonMandatoryFieldInFile(t *testing.T) {
	t.Log("Testing missing non-mandatory field in file...")
	tmpfile, _ := createTempFileWithObject(t, struct {
		Field1 string `mandatory:"true"`
	}{
		Field1: "test",
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStruct
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: missing non-mandatory field in file")
	}
}

func testStructWithAnonymousField(t *testing.T) {
	t.Log("Testing struct with anonymous field...")
	type TestStructWithAnonymous struct {
		TestStruct
		Field3 string
	}
	tmpfile, _ := createTempFileWithObject(t, TestStructWithAnonymous{
		TestStruct: TestStruct{
			Field1: "test",
			Field2: 123,
		},
		Field3: "extra",
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStructWithAnonymous
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: struct with anonymous field")
	}
}

func testNestedStructs(t *testing.T) {
	t.Log("Testing nested structs...")
	type NestedStruct struct {
		Field1 string `mandatory:"true"`
		Field2 int
	}
	type TestStructWithNested struct {
		Field1 string `mandatory:"true"`
		Field2 NestedStruct
	}
	tmpfile, testObject := createTempFileWithObject(t, TestStructWithNested{
		Field1: "test",
		Field2: NestedStruct{
			Field1: "nested",
			Field2: 456,
		},
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStructWithNested
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: nested structs")
	}
	if result != testObject {
		t.Errorf("expected %v, got %v", testObject, result)
	}
}

func testArrayOfStructs(t *testing.T) {
	t.Log("Testing array of structs...")
	type ArrayElementStruct struct {
		Field1 string `mandatory:"true"`
		Field2 int
	}
	type TestStructWithArray struct {
		Field1 string `mandatory:"true"`
		Field2 []ArrayElementStruct
	}
	tmpfile, testObject := createTempFileWithObject(t, TestStructWithArray{
		Field1: "test",
		Field2: []ArrayElementStruct{
			{
				Field1: "element1",
				Field2: 456,
			},
			{
				Field1: "element2",
				Field2: 789,
			},
		},
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result TestStructWithArray
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: array of structs")
	}
	if !reflect.DeepEqual(result, testObject) {
		t.Errorf("expected %v, got %v", testObject, result)
	}
}

func testAnonymousStructs(t *testing.T) {
	t.Log("Testing anonymous structs...")
	tmpfile, testObject := createTempFileWithObject(t, struct {
		Field1 string `mandatory:"true"`
		Field2 int
	}{
		Field1: "test",
		Field2: 123,
	})
	defer os.Remove(tmpfile.Name()) // clean up

	var result struct {
		Field1 string `mandatory:"true"`
		Field2 int
	}
	err := DeserializeToStruct(tmpfile.Name(), &result)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	} else {
		t.Log("Success: anonymous structs")
	}
	if result != testObject {
		t.Errorf("expected %v, got %v", testObject, result)
	}
}

func createTempFileWithObject(t *testing.T, object interface{}) (tmpfile *os.File, testObject interface{}) {
	tmpfile, err := os.CreateTemp("", "example")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpfile.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}
	return tmpfile, object
}
