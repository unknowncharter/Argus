package main

import (
	"encoding/binary"
	"testing"
)

func buildRawFork(parentPID, childPID uint32, tsNs uint64) []byte {
	buf := make([]byte, 8+16)
	binary.LittleEndian.PutUint32(buf[0:4], eventFork)
	binary.LittleEndian.PutUint32(buf[4:8], 16)
	binary.LittleEndian.PutUint32(buf[8:12], parentPID)
	binary.LittleEndian.PutUint32(buf[12:16], childPID)
	binary.LittleEndian.PutUint64(buf[16:24], tsNs)
	return buf
}

func buildRawExec(pid uint32, tsNs uint64, comm string) []byte {
	const commLen = 16
	if len(comm) > commLen {
		comm = comm[:commLen]
	}
	commBytes := make([]byte, commLen)
	copy(commBytes, comm)
	payloadLen := 4 + 4 + 8 + commLen // pid, padding, ts_ns, comm (daemon reads comm at 16:32)
	buf := make([]byte, 8+payloadLen)
	binary.LittleEndian.PutUint32(buf[0:4], eventExec)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(payloadLen))
	binary.LittleEndian.PutUint32(buf[8:12], pid)
	binary.LittleEndian.PutUint64(buf[16:24], tsNs)
	copy(buf[24:24+commLen], commBytes)
	return buf
}

func buildRawExit(pid uint32, exitCode uint32, tsNs uint64) []byte {
	buf := make([]byte, 8+16)
	binary.LittleEndian.PutUint32(buf[0:4], eventExit)
	binary.LittleEndian.PutUint32(buf[4:8], 16)
	binary.LittleEndian.PutUint32(buf[8:12], pid)
	binary.LittleEndian.PutUint32(buf[12:16], exitCode)
	binary.LittleEndian.PutUint64(buf[16:24], tsNs)
	return buf
}

func TestProcessLineage_RootOnly(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)

	if got := store.RootPID(); got != rootPID {
		t.Errorf("RootPID() = %d, want %d", got, rootPID)
	}
	procTable, children, events, _, _ := store.Snapshot(0)
	if len(procTable) != 1 || procTable[rootPID] == nil {
		t.Fatalf("expected root %d in proc table, got %d entries", rootPID, len(procTable))
	}
	if procTable[rootPID].Ppid != 0 {
		t.Errorf("root should have Ppid 0, got %d", procTable[rootPID].Ppid)
	}
	if len(children) != 0 {
		t.Errorf("expected no children yet, got %v", children)
	}
	if len(events) != 0 {
		t.Errorf("expected no events yet, got %d", len(events))
	}
}

func TestProcessLineage_OneChild(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	childPID := uint32(1001)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)

	ts := uint64(1_000_000)
	store.Ingest(buildRawFork(rootPID, childPID, ts))

	procTable, children, events, _, _ := store.Snapshot(0)
	if len(procTable) != 2 {
		t.Fatalf("expected 2 entries (root + child), got %d", len(procTable))
	}
	if procTable[childPID] == nil {
		t.Fatal("child should be in proc table")
	}
	if procTable[childPID].Ppid != rootPID {
		t.Errorf("child Ppid should be %d, got %d", rootPID, procTable[childPID].Ppid)
	}
	if len(children) != 1 || len(children[rootPID]) != 1 || children[rootPID][0] != childPID {
		t.Errorf("expected children[%d]=[%d], got %v", rootPID, childPID, children)
	}
	if len(events) != 1 || events[0].Type != "fork" || events[0].Pid != childPID || events[0].Ppid != rootPID {
		t.Errorf("expected one fork event for child, got %+v", events)
	}
}

func TestProcessLineage_TransitiveClosure(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	childPID := uint32(1001)
	grandchildPID := uint32(1002)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)

	ts := uint64(1_000_000)
	store.Ingest(buildRawFork(rootPID, childPID, ts))
	store.Ingest(buildRawFork(childPID, grandchildPID, ts+1))

	procTable, children, _, _, _ := store.Snapshot(0)
	if len(procTable) != 3 {
		t.Fatalf("expected 3 entries (root, child, grandchild), got %d", len(procTable))
	}
	if procTable[grandchildPID].Ppid != childPID {
		t.Errorf("grandchild Ppid should be %d, got %d", childPID, procTable[grandchildPID].Ppid)
	}
	if len(children[rootPID]) != 1 || children[rootPID][0] != childPID {
		t.Errorf("root children should be [%d], got %v", childPID, children[rootPID])
	}
	if len(children[childPID]) != 1 || children[childPID][0] != grandchildPID {
		t.Errorf("child children should be [%d], got %v", grandchildPID, children[childPID])
	}
}

func TestProcessLineage_ExecUpdatesComm(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	childPID := uint32(1001)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)
	store.Ingest(buildRawFork(rootPID, childPID, 1))

	store.Ingest(buildRawExec(childPID, 2, "bash"))

	procTable, _, _, _, _ := store.Snapshot(0)
	if procTable[childPID].Comm != "bash" {
		t.Errorf("expected child comm \"bash\", got %q", procTable[childPID].Comm)
	}
}

func TestProcessLineage_ExitMarksExited(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	childPID := uint32(1001)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)
	store.Ingest(buildRawFork(rootPID, childPID, 1))

	store.Ingest(buildRawExit(childPID, 0, 2))

	procTable, _, events, _, _ := store.Snapshot(0)
	if !procTable[childPID].Exited {
		t.Error("child should be marked Exited")
	}
	if procTable[childPID].ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", procTable[childPID].ExitCode)
	}
	var exitEv *NormalizedEvent
	for i := range events {
		if events[i].Type == "exit" && events[i].Pid == childPID {
			exitEv = &events[i]
			break
		}
	}
	if exitEv == nil {
		t.Fatal("expected one exit event for child")
	}
	if exitEv.ExitCode == nil || *exitEv.ExitCode != 0 {
		t.Errorf("exit event should have exit_code 0, got %v", exitEv.ExitCode)
	}
}

func TestProcessLineage_EventOrderForkExecExit(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	childPID := uint32(1001)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)

	store.Ingest(buildRawFork(rootPID, childPID, 100))
	store.Ingest(buildRawExec(childPID, 101, "mini"))
	store.Ingest(buildRawExit(childPID, 0, 102))

	_, _, events, _, _ := store.Snapshot(0)
	if len(events) < 3 {
		t.Fatalf("expected at least 3 events, got %d", len(events))
	}
	types := make([]string, 0, 3)
	for _, e := range events {
		if e.Pid == childPID && (e.Type == "fork" || e.Type == "exec" || e.Type == "exit") {
			types = append(types, e.Type)
		}
	}
	if len(types) != 3 || types[0] != "fork" || types[1] != "exec" || types[2] != "exit" {
		t.Errorf("expected event order fork, exec, exit for child; got %v", types)
	}
}

// TestPortAwareConnectMatching verifies that a connection to localhost:9999 is NOT
// matched as structural when the session intent only mentions localhost:8888.
// This is the core regression test for the port-aware connect matching fix.
func TestPortAwareConnectMatching(t *testing.T) {
	const pid = uint32(5000)

	inject := func(store *Store, snippet string) {
		store.mu.Lock()
		store.recentLLMByPid[pid] = append(store.recentLLMByPid[pid], snippet)
		store.mu.Unlock()
	}

	// Intent only mentions localhost:8888 (the benign mock server port).
	intent := "Fetch http://localhost:8888/web/python and summarize the output."

	t.Run("port_8888_matches", func(t *testing.T) {
		store := NewStore(5000, 8192, nil)
		inject(store, intent)
		store.mu.RLock()
		got := store.connectHostPortInLLMSnippetsUnlocked(pid, "localhost", 8888)
		store.mu.RUnlock()
		if !got {
			t.Error("expected localhost:8888 to match when intent contains localhost:8888")
		}
	})

	t.Run("port_9999_no_match", func(t *testing.T) {
		store := NewStore(5000, 8192, nil)
		inject(store, intent)
		store.mu.RLock()
		got := store.connectHostPortInLLMSnippetsUnlocked(pid, "localhost", 9999)
		store.mu.RUnlock()
		if got {
			t.Error("expected localhost:9999 NOT to match when intent only contains localhost:8888")
		}
	})

	t.Run("standard_port_80_always_matches", func(t *testing.T) {
		store := NewStore(5000, 8192, nil)
		inject(store, intent)
		store.mu.RLock()
		got := store.connectHostPortInLLMSnippetsUnlocked(pid, "localhost", 80)
		store.mu.RUnlock()
		if !got {
			t.Error("expected standard port 80 to match when hostname appears in intent")
		}
	})

	t.Run("hostname_without_port_matches_any_port", func(t *testing.T) {
		// If intent mentions hostname without an explicit port, any port should match.
		store := NewStore(5000, 8192, nil)
		inject(store, "connect to example.com for documentation")
		store.mu.RLock()
		got := store.connectHostPortInLLMSnippetsUnlocked(pid, "example.com", 9999)
		store.mu.RUnlock()
		if !got {
			t.Error("expected any port to match when hostname appears without explicit port in intent")
		}
	})
}

func TestProcessLineage_MultipleChildren(t *testing.T) {
	store := NewStore(5000, 8192, nil)
	rootPID := uint32(1000)
	c1, c2 := uint32(1001), uint32(1002)
	store.SetRootPID(rootPID)
	store.SeedRootPID(rootPID)

	store.Ingest(buildRawFork(rootPID, c1, 1))
	store.Ingest(buildRawFork(rootPID, c2, 2))

	_, children, _, _, _ := store.Snapshot(0)
	if len(children[rootPID]) != 2 {
		t.Fatalf("root should have 2 children, got %v", children[rootPID])
	}
	seen := make(map[uint32]bool)
	for _, pid := range children[rootPID] {
		seen[pid] = true
	}
	if !seen[c1] || !seen[c2] {
		t.Errorf("expected children %d and %d, got %v", c1, c2, children[rootPID])
	}
}
