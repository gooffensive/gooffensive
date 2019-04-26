package process

import "testing"

//func GetProcess(name string, pid uint32) (WindowsProcess, error) {
func TestGetProcess(t *testing.T) {
	//provide process name, no pid
	//valid process name
	p, err := GetProcess("explorer.exe", 0)
	if err != nil {
		t.Error("error on getting explorer.exe", err)
	}
	//invalid process name
	p, err = GetProcess("exXxXxXplorer.exe", 0)
	if err == nil {
		t.Error("managed to get non-existant process?")
	}

	//proivde no process name, pid
	p, err = GetProcess("", 4)
	//valid
	if err != nil {
		t.Error("error getting system pid (4)", err)
	}
	//invalid
	p, err = GetProcess("", 1)
	if err == nil || p.Pid == 1 {
		t.Error("error non-existant pid (1)", err)
	}

	//provide process name, pid
	p, err = GetProcess("explorer.exe", 4) //check things
	if err != nil {
		t.Error("error getting proces via pid (4)", err)
	}
	if err == nil && p.Pid != 4 {
		t.Error("error getting process via pid (4) when name used too", err)
	}
	//provide no process name, no pid
	p, err = GetProcess("", 1) //check things
	if err == nil {
		t.Error("somehow got a process with invalid name and number", err)
	}
}

//func GetProcesses() (procs []WindowsProcess, err error) {
func TestGetProcesses(t *testing.T) {
	//todo:
}
