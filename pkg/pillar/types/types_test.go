package types

import (
  "testing"
  "errors"
  log "github.com/sirupsen/logrus"
)
type TestUrlToSafenameMatrixEntry struct {
  safename  string
  url       string
  sha       string
}
type TestSafenameToFilenameMatrixEntry struct {
  safename  string
  filename  string
}

type TestParseTriStateMatrixEntry struct {
  err  error
  ts TriState
  value     string
}

// Test Completed, needs input/output
func TestUrlToSafename(t *testing.T) {
	log.Infof("TestLookupIoBundle: START\n")
	testMatrix = []TestUrlToSafenameMatrixEntry{
    {safename: "helloworld", url: "helloworld", sha: "helloworld"},
    {safename: "helloworld", url: "helloworld", sha: "helloworld"},
  }
  for index := range testMatrix {
    entry := &testMatrix[index]
    safename := UrlToSafename(entry.url, entry.sha)
    if safename != entry.safename {
      t.Errorf("Test Entry Index %d Failed: Expected %t, Actual: %t\n",
				index, entry.safename, safename)
    }
  }
	log.Infof("TestLookupIoBundle: DONE\n")
}

// Test Completed, needs input/output
func TestSafenameToFilename(t *testing.T) {
	log.Infof("TestLookupIoBundle: START\n")
  testMatrix := []TestSafenameToFilenameMatrixEntry{
		{safename: "helloworld", filename: "helloworld"},
		{safename: "helloworld", filename: "helloworld"},
		{safename: "helloworld", filename: "helloworld"},
		{safename: "helloworld", filename: "helloworld"},
		{safename: "helloworld", filename: "helloworld"},
	}

  for index := range testMatrix {
		entry := &testMatrix[index]
		filename := SafenameToFilename(entry.safename)
    if filename != entry.filename {
			t.Errorf("Test Entry Index %d Failed: Expected %t, Actual: %t\n",
				index, entry.filename, filename)
		}
  }
	log.Infof("TestLookupIoBundle: DONE\n")
}

func TestParseTriState(t *testing.T) {
	log.Infof("TestLookupIoBundle: START\n")
  testMatrix := []TestParseTriStateMatrixEntry{
		{err: "helloworld", ts = "helloworld", value: "hello"},
		{err: "helloworld", ts = "helloworld", value: "hello"},
    {err: "helloworld", ts = "helloworld", value: "hello"},
    {err: "helloworld", ts = "helloworld", value: "hello"},
    {err: "helloworld", ts = "helloworld", value: "hello"},
	}

  for index := range testMatrix {
		entry := &testMatrix[index]
		ts, err := ParseTriState(entry.value)
    if ts != entry.ts {
			t.Errorf("Test Entry Index %d Failed: Expected TS: %t, Actual TS: %t\n",
				index, entry.ts, ts)
		}
    else if err != entry.err {
      t.Errorf("Test Entry Index %d Failed: Expected Error: %t, Actual Error: %t\n",
				index, entry.err, err)
    }
  }
	log.Infof("TestLookupIoBundle: DONE\n")
}
