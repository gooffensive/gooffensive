// +build windows

package gooffensive

import (
	"bytes"
	"testing"

	offensiveProcess "github.com/gooffensive/gooffensive/pkg/gooffensive/process"
)

func TestMinidump(t *testing.T) {
	//taken from the tests provided to the merlin project (https://github.com/Ne0nd0g/merlin)

	// Check a good minidump works
	procName, pid, byts, err := MiniDump("", "go.exe", 0)

	if err != nil {
		t.Error("Failed minidump on known process (possible false positive if run in non-windows environment somehow):", err)
	}
	if bytes.Compare(byts[:4], []byte("MDMP")) != 0 {
		t.Error("Invalid minidump file produced (based on file header)")
	}

	// Check a minidump on an unknown proc doesn't work
	procName, pid, _, err = MiniDump("", "notarealprocess.exe", 0)
	if err == nil {
		t.Error("Found process when it shouldn't have...")
	}

	// Check a minidump providing a pid with blank string works
	proc, err := offensiveProcess.GetProcess("go.exe", 0)
	procName, pid, byts, err = MiniDump("", "", proc.Pid)

	if err != nil || len(byts) == 0 {
		t.Error("Minidump using pid failed")
	}

	// Verify proc name matches
	if procName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", procName)
	}

	// Check a minidump with a valid pid but invalid string works (pid should take priority)
	procName, pid, byts, err = MiniDump("", "notarealprocess.exe", pid)
	if err != nil || len(byts) == 0 {
		t.Error("Minidump using valid pid and invalid proc name failed")
	}

	// Verify proc name matches
	if procName != "go.exe" {
		t.Error("Minidump proc name does not match: ", "go.exe", procName)
	}

	// Check a minidump with a valid proc name, but invalid pid fails
	procName, pid, byts, err = MiniDump("", "go.exe", 123456789)
	if err == nil {
		t.Error("Minidump dumped a process even though provided pid was invalid")
	}

	// Check for non-existing path (dir)
	procName, pid, byts, err = MiniDump("C:\\thispathbetternot\\exist\\", "go.exe", 0)
	if err == nil {
		t.Error("Didn't get an error on non-existing path (check to make sure hte path doesn't actually exist)")
	}

	// Check for existing path (dir)
	procName, pid, byts, err = MiniDump("C:\\Windows\\temp\\", "go.exe", 0)
	if err != nil {
		t.Error("Got an error on existing path (check to make sure the path actually exists)")
		t.Error(err)
	}

	// Check for existing file
	procName, pid, byts, err = MiniDump("C:\\Windows\\System32\\calc.exe", "go.exe", 0)
	if err == nil {
		t.Error("Didn't get an error on existing file (check to make sure the path & file actually exist)")
	}

}
