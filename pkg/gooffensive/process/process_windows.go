package process

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// WindowsProcess represents a process object
type WindowsProcess struct {
	Pid        uint32
	PPid       uint32
	Executable string
	Owner      string
}

// GetProcess takes in a process name OR a process ID and returns a pointer to the process handle, the process name,
// and the process ID. If both a process name and a PID are provided, the PID is used.
func GetProcess(name string, pid uint32) (WindowsProcess, error) {
	p := WindowsProcess{}
	if pid <= 0 && name == "" {
		return p, fmt.Errorf("a process name OR process ID must be provided")
	}
	procs, err := GetProcesses()
	if err != nil {
		return p, err
	}
	for _, proc := range procs {
		if pid > 0 {
			if proc.Pid == pid {
				return proc, nil
			}
		} else if proc.Executable == name {
			return proc, nil
		}
	}
	return p, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}

// GetProcesses returns a list of all the running processes
func GetProcesses() (procs []WindowsProcess, err error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go
	procs = make([]WindowsProcess, 0)
	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if snapshotHandle < 0 || err != nil {
		return procs, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return procs, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		p := WindowsProcess{}
		for _, chr := range process.ExeFile {
			if chr != 0 {
				p.Executable = p.Executable + string(int(chr))
			}
		}
		p.PPid = process.ParentProcessID
		p.Pid = process.ProcessID
		p.Owner, _ = getProcessOwner(p.Pid)
		procs = append(procs, p)

		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			if strings.Compare(err.Error(), "There are no more files.") == 0 {
				return procs, nil
			}
			break
		}
	}
	return
}

// Helper functions

// getInfo retrieves a specified type of information about an access token.
func getInfo(t syscall.Token, class uint32, initSize int) (unsafe.Pointer, error) {
	n := uint32(initSize)
	for {
		b := make([]byte, n)
		e := syscall.GetTokenInformation(t, class, &b[0], uint32(len(b)), &n)
		if e == nil {
			return unsafe.Pointer(&b[0]), nil
		}
		if e != syscall.ERROR_INSUFFICIENT_BUFFER {
			return nil, e
		}
		if n <= uint32(len(b)) {
			return nil, e
		}
	}
}

func getTokenUser(t syscall.Token) (*syscall.Tokenuser, error) {
	i, e := getInfo(t, syscall.TokenUser, 50)
	if e != nil {
		return nil, e
	}
	return (*syscall.Tokenuser)(i), nil
}

// getTokenOwner retrieves access token t owner account information.
func getTokenOwner(t syscall.Token) (*syscall.Tokenuser, error) {
	i, e := getInfo(t, syscall.TokenOwner, 50)
	if e != nil {
		return nil, e
	}
	return (*syscall.Tokenuser)(i), nil
}

func getProcessOwner(pid uint32) (owner string, err error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return
	}
	var token syscall.Token
	if err = syscall.OpenProcessToken(handle, syscall.TOKEN_QUERY, &token); err != nil {
		return
	}
	tokenUser, err := getTokenUser(token)
	if err != nil {
		tokenUser, err = getTokenOwner(token)
		if err != nil {
			return
		}
	}
	owner, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	owner = fmt.Sprintf("%s\\%s", domain, owner)
	return
}
