"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  ProcTable,
  ChildrenMap,
  NormalizedEvent,
  FlowRec,
  SSLEventRec,
  SnapshotMessage,
} from "./types";

const MAX_DISPLAY_EVENTS = 5000;
export const EVENT_TYPES = [
  "fork",
  "exec",
  "exit",
  "connect",
  "ssl",
  "openat",
  "close",
  "dup",
  "dup2",
  "read",
  "write",
  "pipe",
  "stat",
  "access",
  "unlink",
  "signal",
  "correlation_alert",
] as const;
export type EventTypeFilter = (typeof EVENT_TYPES)[number];

const defaultFilters: Record<EventTypeFilter, boolean> = {
  fork: true,
  exec: true,
  exit: true,
  connect: true,
  ssl: true,
  openat: true,
  close: true,
  dup: true,
  dup2: true,
  read: true,
  write: true,
  pipe: true,
  stat: true,
  access: true,
  unlink: true,
  signal: true,
  correlation_alert: true,
};

export function useObserverState(wsUrl: string) {
  const [connected, setConnected] = useState(false);
  const [procTable, setProcTable] = useState<ProcTable>({});
  const [children, setChildren] = useState<ChildrenMap>({});
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [flows, setFlows] = useState<Record<string, FlowRec[]>>({});
  const [sslEvents, setSslEvents] = useState<SSLEventRec[]>([]);
  const [selectedPid, setSelectedPid] = useState<number | null>(null);
  const [filters, setFiltersState] = useState<Record<EventTypeFilter, boolean>>(
    defaultFilters
  );
  const [searchQuery, setSearchQuery] = useState("");
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<ReturnType<typeof setTimeout>>();

  const setFilter = useCallback((type: EventTypeFilter, value: boolean) => {
    setFiltersState((prev) => ({ ...prev, [type]: value }));
  }, []);

  useEffect(() => {
    if (!wsUrl) return;

    function connect() {
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => setConnected(true);
      ws.onclose = () => {
        setConnected(false);
        reconnectTimeoutRef.current = setTimeout(connect, 2000);
      };
      ws.onerror = () => {};

      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data as string);
          if (msg.type === "snapshot") {
            const snap = msg as SnapshotMessage;
            setProcTable(snap.proc_table ?? {});
            setChildren(snap.children ?? {});
            setEvents((prev) => {
              const next = snap.events ?? [];
              return next.length > MAX_DISPLAY_EVENTS
                ? next.slice(-MAX_DISPLAY_EVENTS)
                : next;
            });
            setFlows(snap.flows ?? {});
            setSslEvents((prev) => {
              const next = snap.ssl ?? [];
              return next.length > 2000 ? next.slice(-2000) : next;
            });
            return;
          }
          if (msg.type === "event_updated") {
            const event = (msg as { event?: NormalizedEvent }).event;
            if (!event?.type || event.pid == null || event.ts_ns == null) return;
            setEvents((prev) => {
              const key = (e: NormalizedEvent) => `${e.pid}:${e.type}:${e.ts_ns}`;
              const targetKey = key(event);
              const idx = prev.findIndex((e) => key(e) === targetKey);
              if (idx === -1) return prev;
              const next = [...prev];
              next[idx] = event;
              return next;
            });
            return;
          }
          const raw = (msg as { type?: string; event?: NormalizedEvent }).event ?? (msg as NormalizedEvent);
          const event = raw as NormalizedEvent;
          const knownTypes = [
            "fork",
            "exec",
            "exit",
            "connect",
            "ssl",
            "openat",
            "close",
            "dup",
            "dup2",
            "read",
            "write",
            "pipe",
            "stat",
            "access",
            "unlink",
            "signal",
            "correlation_alert",
          ];
          if (!event?.type || !knownTypes.includes(event.type)) return;
          setEvents((prev) => {
            const next = [...prev, event];
            return next.length > MAX_DISPLAY_EVENTS
              ? next.slice(-MAX_DISPLAY_EVENTS)
              : next;
          });
          if (event.type === "ssl") {
            setSslEvents((prev) => {
              const rec = {
                Pid: event.pid ?? 0,
                Tid: 0,
                Ts: event.ts_ns ?? 0,
                Direction: (event.direction ?? "tx") as "tx" | "rx",
                Nbytes: event.nbytes ?? 0,
                Snippet: event.snippet ?? "",
                Binary: event.binary,
              };
              const next = [...prev, rec];
              return next.length > 2000 ? next.slice(-2000) : next;
            });
          }
          if (event.type === "connect") {
            setFlows((prev) => {
              const pid = String(event.pid ?? 0);
              const list = prev[pid] ?? [];
              const family = event.family === "IPv6" ? 10 : 2;
              const next = {
                ...prev,
                [pid]: [
                  ...list,
                  {
                    DstIP: event.dst_ip ?? "",
                    DstPort: event.dst_port ?? 0,
                    Family: family,
                    Ts: event.ts_ns ?? 0,
                  },
                ].slice(-100),
              };
              return next;
            });
          }
          if (event.type === "exec" || event.type === "fork") {
            setProcTable((prev) => {
              const pid = String(event.pid ?? 0);
              const existing = prev[pid];
              return {
                ...prev,
                [pid]: {
                  Ppid: event.ppid ?? existing?.Ppid ?? 0,
                  Comm: event.comm ?? existing?.Comm ?? "",
                  Exe: event.exe ?? existing?.Exe ?? "",
                  Cmdline: event.cmdline ?? existing?.Cmdline ?? "",
                  FirstSeen: existing?.FirstSeen ?? event.ts_ns ?? 0,
                  LastSeen: event.ts_ns ?? 0,
                },
              };
            });
            if (event.type === "fork" && event.ppid != null) {
              setChildren((prev) => {
                const ppid = String(event.ppid);
                const list = prev[ppid] ?? [];
                if (list.includes(event.pid!)) return prev;
                return { ...prev, [ppid]: [...list, event.pid!] };
              });
            }
          }
          if (event.type === "exit") {
            setProcTable((prev) => {
              const pid = String(event.pid ?? 0);
              const p = prev[pid];
              if (!p) return prev;
              return {
                ...prev,
                [pid]: { ...p, Exited: true, ExitCode: event.exit_code },
              };
            });
          }
        } catch (_) {}
      };
    }

    connect();
    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [wsUrl]);

  return {
    connected,
    procTable,
    children,
    events,
    flows,
    sslEvents,
    selectedPid,
    setSelectedPid,
    filters,
    setFilter,
    searchQuery,
    setSearchQuery,
  };
}
