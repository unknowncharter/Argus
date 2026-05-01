// Types for daemon WebSocket payloads

export interface ProcInfo {
  Ppid: number;
  Comm: string;
  Exe: string;
  Cmdline: string;
  FirstSeen: number;
  LastSeen: number;
  Exited?: boolean;
  ExitCode?: number;
}

export type ProcTable = Record<string, ProcInfo>;

export type ChildrenMap = Record<string, number[]>;

export interface FlowRec {
  DstIP: string;
  DstPort: number;
  Family: number;
  Ts: number;
}

export interface SSLEventRec {
  Pid: number;
  Tid: number;
  Ts: number;
  Direction: "tx" | "rx";
  Nbytes: number;
  Snippet: string;
  Binary?: boolean;
}

export interface NormalizedEvent {
  type: string;
  ts_ns: number;
  ts_iso: string;
  pid?: number;
  ppid?: number;
  comm?: string;
  exe?: string;
  cmdline?: string;
  exit_code?: number;
  dst_ip?: string;
  dst_host?: string;
  dst_port?: number;
  family?: string;
  direction?: string;
  nbytes?: number;
  snippet?: string;
  binary?: boolean;
  path?: string;
  fd?: number;
  count?: number;
  oldfd?: number;
  newfd?: number;
  env?: Record<string, string>;
  match_type?: string;
  auditor_reason?: string;
  correlation_pattern?: string;
  correlation_events?: NormalizedEvent[];
}

export interface SnapshotMessage {
  type: "snapshot";
  root_pid?: number;
  proc_table: ProcTable;
  children: ChildrenMap;
  events: NormalizedEvent[];
  flows: Record<string, FlowRec[]>;
  ssl: SSLEventRec[];
}
