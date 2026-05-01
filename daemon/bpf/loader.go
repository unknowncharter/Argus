package bpf

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// AgentObserverObjects holds loaded BPF maps and programs.
type AgentObserverObjects struct {
	InterestingPids         *ebpf.Map
	SSLReadCtx              *ebpf.Map
	Events                  *ebpf.Map
	TpSchedProcessFork      *ebpf.Program
	TpSchedProcessExec      *ebpf.Program
	TpSchedProcessExit      *ebpf.Program
	TpSysEnterKill          *ebpf.Program
	TpSysEnterTgkill        *ebpf.Program
	TpSysEnterTkill         *ebpf.Program
	TpSysEnterConnect       *ebpf.Program
	TpSysEnterPipe          *ebpf.Program
	TpSysExitPipe           *ebpf.Program
	TpSysEnterPipe2         *ebpf.Program
	TpSysExitPipe2          *ebpf.Program
	TpSysEnterOpenat        *ebpf.Program
	TpSysExitOpenat         *ebpf.Program
	TpSysEnterClose        *ebpf.Program
	TpSysEnterRead          *ebpf.Program
	TpSysExitRead           *ebpf.Program
	TpSysEnterWrite         *ebpf.Program
	TpSysExitWrite          *ebpf.Program
	TpSysEnterDup           *ebpf.Program
	TpSysExitDup            *ebpf.Program
	TpSysEnterDup2          *ebpf.Program
	TpSysExitDup2           *ebpf.Program
	TpSysEnterStatx         *ebpf.Program
	TpSysExitStatx          *ebpf.Program
	TpSysEnterFaccessat     *ebpf.Program
	TpSysExitFaccessat      *ebpf.Program
	TpSysEnterUnlinkat      *ebpf.Program
	TpSysExitUnlinkat       *ebpf.Program
	UprobeSSLWrite          *ebpf.Program
	UprobeSSLWriteEx        *ebpf.Program
	UprobeSSLReadEntry      *ebpf.Program
	UretprobeSSLReadExit    *ebpf.Program
	UprobeSSLReadExEntry    *ebpf.Program
	UretprobeSSLReadExExit  *ebpf.Program
	UprobeGetaddrinfoEntry  *ebpf.Program
	UretprobeGetaddrinfoExit *ebpf.Program
	coll                    *ebpf.Collection
}

func LoadAgentObserver() (*AgentObserverObjects, error) {
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	paths := []string{
		filepath.Join(cwd, "bpf", "agent_observer.bpf.o"),
		filepath.Join(cwd, "daemon", "..", "bpf", "agent_observer.bpf.o"),
		filepath.Join(exeDir, "bpf", "agent_observer.bpf.o"),
		filepath.Join(exeDir, "agent_observer.bpf.o"),
		"bpf/agent_observer.bpf.o",
		"agent_observer.bpf.o",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			abs, _ := filepath.Abs(path)
			log.Printf("bpf: loading %s", abs)
			return loadFrom(path)
		}
	}
	return nil, fmt.Errorf("bpf object not found; tried %v (cwd: %s)", paths, cwd)
}

func loadFrom(path string) (*AgentObserverObjects, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("new collection: %w", err)
	}
	objs := &AgentObserverObjects{coll: coll}
	objs.InterestingPids, _ = coll.Maps["interesting_pids"]
	objs.SSLReadCtx, _ = coll.Maps["ssl_read_ctx"]
	objs.Events, _ = coll.Maps["events"]
	objs.TpSchedProcessFork, _ = coll.Programs["tp_sched_process_fork"]
	objs.TpSchedProcessExec, _ = coll.Programs["tp_sched_process_exec"]
	objs.TpSchedProcessExit, _ = coll.Programs["tp_sched_process_exit"]
	objs.TpSysEnterKill, _ = coll.Programs["tp_sys_enter_kill"]
	objs.TpSysEnterTgkill, _ = coll.Programs["tp_sys_enter_tgkill"]
	objs.TpSysEnterTkill, _ = coll.Programs["tp_sys_enter_tkill"]
	objs.TpSysEnterConnect, _ = coll.Programs["tp_sys_enter_connect"]
	objs.TpSysEnterPipe, _ = coll.Programs["tp_sys_enter_pipe"]
	objs.TpSysExitPipe, _ = coll.Programs["tp_sys_exit_pipe"]
	objs.TpSysEnterPipe2, _ = coll.Programs["tp_sys_enter_pipe2"]
	objs.TpSysExitPipe2, _ = coll.Programs["tp_sys_exit_pipe2"]
	objs.TpSysEnterOpenat, _ = coll.Programs["tp_sys_enter_openat"]
	objs.TpSysExitOpenat, _ = coll.Programs["tp_sys_exit_openat"]
	objs.TpSysEnterClose, _ = coll.Programs["tp_sys_enter_close"]
	objs.TpSysEnterRead, _ = coll.Programs["tp_sys_enter_read"]
	objs.TpSysExitRead, _ = coll.Programs["tp_sys_exit_read"]
	objs.TpSysEnterWrite, _ = coll.Programs["tp_sys_enter_write"]
	objs.TpSysExitWrite, _ = coll.Programs["tp_sys_exit_write"]
	objs.TpSysEnterDup, _ = coll.Programs["tp_sys_enter_dup"]
	objs.TpSysExitDup, _ = coll.Programs["tp_sys_exit_dup"]
	objs.TpSysEnterDup2, _ = coll.Programs["tp_sys_enter_dup2"]
	objs.TpSysExitDup2, _ = coll.Programs["tp_sys_exit_dup2"]
	objs.TpSysEnterStatx, _ = coll.Programs["tp_sys_enter_statx"]
	objs.TpSysExitStatx, _ = coll.Programs["tp_sys_exit_statx"]
	objs.TpSysEnterFaccessat, _ = coll.Programs["tp_sys_enter_faccessat"]
	objs.TpSysExitFaccessat, _ = coll.Programs["tp_sys_exit_faccessat"]
	objs.TpSysEnterUnlinkat, _ = coll.Programs["tp_sys_enter_unlinkat"]
	objs.TpSysExitUnlinkat, _ = coll.Programs["tp_sys_exit_unlinkat"]
	objs.UprobeSSLWrite, _ = coll.Programs["uprobe_SSL_write"]
	objs.UprobeSSLWriteEx, _ = coll.Programs["uprobe_SSL_write_ex"]
	objs.UprobeSSLReadEntry, _ = coll.Programs["uprobe_SSL_read_entry"]
	objs.UretprobeSSLReadExit, _ = coll.Programs["uretprobe_SSL_read_exit"]
	objs.UprobeSSLReadExEntry, _ = coll.Programs["uprobe_SSL_read_ex_entry"]
	objs.UretprobeSSLReadExExit, _ = coll.Programs["uretprobe_SSL_read_ex_exit"]
	objs.UprobeGetaddrinfoEntry, _ = coll.Programs["uprobe_getaddrinfo_entry"]
	objs.UretprobeGetaddrinfoExit, _ = coll.Programs["uretprobe_getaddrinfo_exit"]
	if objs.InterestingPids == nil || objs.Events == nil || objs.TpSchedProcessFork == nil ||
		objs.TpSysEnterKill == nil || objs.TpSysEnterTgkill == nil || objs.TpSysEnterTkill == nil {
		coll.Close()
		return nil, fmt.Errorf("missing required map or program")
	}
	return objs, nil
}

func (o *AgentObserverObjects) Close() error {
	if o.coll != nil {
		o.coll.Close()
		o.coll = nil
	}
	return nil
}
