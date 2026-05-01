"use client";

import { useMemo, useState, useCallback, useRef, useEffect } from "react";
import type { NormalizedEvent } from "./types";
import type { ProcTable, ChildrenMap } from "./types";
import { EVENT_TYPES, type EventTypeFilter } from "./useObserverState";

const EVENT_GROUPS: { heading: string; groupId: string; types: EventTypeFilter[] }[] = [
  { heading: "Lifecycle", groupId: "lifecycle", types: ["fork", "exec", "exit"] },
  { heading: "Network", groupId: "network", types: ["connect", "ssl"] },
  { heading: "I/O", groupId: "io", types: ["read", "write", "pipe"] },
  { heading: "FDs", groupId: "fds", types: ["openat", "close", "dup", "dup2"] },
  { heading: "FS", groupId: "fs", types: ["stat", "access", "unlink"] },
  { heading: "Control", groupId: "control", types: ["signal"] },
  { heading: "Correlation", groupId: "correlation", types: ["correlation_alert"] },
];

const PRIMARY_SYSCALLS: Set<EventTypeFilter> = new Set([
  "connect", "fork", "openat", "read", "stat",
]);

function getGroupForType(type: string): string {
  for (const g of EVENT_GROUPS) {
    if (g.types.includes(type as EventTypeFilter)) return g.groupId;
  }
  return "neutral";
}

function isPrimarySyscall(type: string): boolean {
  return PRIMARY_SYSCALLS.has(type as EventTypeFilter);
}

function eventMatchesSearch(ev: NormalizedEvent, q: string): boolean {
  if (!q.trim()) return true;
  const lower = q.toLowerCase();
  const envStr = ev.env
    ? Object.entries(ev.env)
        .map(([k, v]) => `${k}=${v}`)
        .join(" ")
    : "";
  const str = [
    ev.exe,
    ev.comm,
    ev.cmdline,
    ev.snippet,
    ev.path,
    ev.dst_host,
    ev.dst_ip,
    envStr,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return str.includes(lower);
}

function formatTs(tsIso: string): string {
  if (!tsIso) return "";
  try {
    const d = new Date(tsIso);
    const t = d.toISOString();
    return t.slice(11, 23);
  } catch {
    return tsIso;
  }
}

function getRootPids(procTable: ProcTable, children: ChildrenMap): number[] {
  const childSet = new Set<number>();
  Object.values(children).forEach((arr) => arr.forEach((p) => childSet.add(p)));
  return Object.entries(procTable)
    .filter(([, info]) => {
      const ppid = (info as { Ppid?: number }).Ppid;
      return ppid === 0 || ppid === undefined;
    })
    .map(([pidStr]) => Number(pidStr))
    .filter((pid) => !childSet.has(pid));
}

export function Timeline({
  events,
  filters,
  setFilter,
  searchQuery,
  selectedPid,
  onClearSelection,
  procTable,
  children: childrenMap,
}: {
  events: NormalizedEvent[];
  filters: Record<EventTypeFilter, boolean>;
  setFilter: (t: EventTypeFilter, v: boolean) => void;
  searchQuery: string;
  selectedPid: number | null;
  onClearSelection?: () => void;
  procTable: ProcTable;
  children: ChildrenMap;
}) {
  const [expandedEventKey, setExpandedEventKey] = useState<string | null>(null);
  const [expandedChildPids, setExpandedChildPids] = useState<Set<number>>(new Set());
  const [openCategory, setOpenCategory] = useState<string | null>(null);
  const [copyFeedback, setCopyFeedback] = useState<"copied" | "failed" | null>(null);
  const [highlightRare, setHighlightRare] = useState(false);
  const categoryDropdownsRef = useRef<HTMLDivElement>(null);
  const copyFeedbackTimeoutRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (categoryDropdownsRef.current && !categoryDropdownsRef.current.contains(e.target as Node)) {
        setOpenCategory(null);
      }
    }
    if (openCategory) {
      document.addEventListener("mousedown", handleClickOutside);
      return () => document.removeEventListener("mousedown", handleClickOutside);
    }
  }, [openCategory]);

  useEffect(() => {
    return () => {
      if (copyFeedbackTimeoutRef.current) clearTimeout(copyFeedbackTimeoutRef.current);
    };
  }, []);

  const toggleChild = useCallback((pid: number) => {
    setExpandedChildPids((prev) => {
      const next = new Set(prev);
      if (next.has(pid)) next.delete(pid);
      else next.add(pid);
      return next;
    });
  }, []);

  const filtered = useMemo(() => {
    let list = events;
    const types = EVENT_TYPES.filter((t) => filters[t]);
    if (types.length < EVENT_TYPES.length) {
      list = list.filter((e) => e.type && types.includes(e.type as EventTypeFilter));
    }
    if (selectedPid != null) {
      list = list.filter((e) => e.pid === selectedPid);
    }
    if (searchQuery.trim()) {
      list = list.filter((e) => eventMatchesSearch(e, searchQuery));
    }
    return list;
  }, [events, filters, selectedPid, searchQuery]);

  const eventsByPid = useMemo(() => {
    const byPid: Record<number, NormalizedEvent[]> = {};
    filtered.forEach((ev) => {
      if (ev.type === "fork") {
        const parentPid = ev.ppid ?? ev.pid;
        if (parentPid == null) return;
        if (!byPid[parentPid]) byPid[parentPid] = [];
        byPid[parentPid].push(ev);
      } else {
        if (ev.pid == null) return;
        if (!byPid[ev.pid]) byPid[ev.pid] = [];
        byPid[ev.pid].push(ev);
      }
    });
    Object.keys(byPid).forEach((pidStr) => {
      const pid = Number(pidStr);
      byPid[pid].sort((a, b) => a.ts_ns - b.ts_ns);
    });
    return byPid;
  }, [filtered]);

  const rootPids = useMemo(() => {
    if (selectedPid != null) return [selectedPid];
    const roots = getRootPids(procTable, childrenMap);
    if (roots.length > 0) return roots;
    const pids = Object.keys(eventsByPid).map(Number);
    const childSet = new Set<number>();
    Object.values(childrenMap).forEach((arr) => arr.forEach((p) => childSet.add(p)));
    return pids.filter((p) => !childSet.has(p));
  }, [selectedPid, procTable, childrenMap, eventsByPid]);

  const commonTypesInFiltered = useMemo(() => {
    if (filtered.length === 0) return new Set<string>();
    const countByType: Record<string, number> = {};
    filtered.forEach((e) => {
      const t = e.type ?? "?";
      countByType[t] = (countByType[t] ?? 0) + 1;
    });
    const total = filtered.length;
    const common = new Set<string>();
    Object.entries(countByType).forEach(([type, n]) => {
      if (n >= total * 0.8) common.add(type);
    });
    return common;
  }, [filtered]);

  const pidsWithEventsInTreeOrder = useMemo(() => {
    const out: { pid: number; depth: number }[] = [];
    function walk(pid: number, depth: number) {
      if ((eventsByPid[pid]?.length ?? 0) > 0) out.push({ pid, depth });
      (childrenMap[String(pid)] ?? []).forEach((c) => walk(c, depth + 1));
    }
    rootPids.forEach((r) => walk(r, 0));
    return out;
  }, [rootPids, childrenMap, eventsByPid]);

  const copyEventJson = useCallback(async (ev: NormalizedEvent) => {
    const str = JSON.stringify(ev, null, 2);
    if (copyFeedbackTimeoutRef.current) clearTimeout(copyFeedbackTimeoutRef.current);
    try {
      if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
        await navigator.clipboard.writeText(str);
        setCopyFeedback("copied");
      } else {
        throw new Error("Clipboard not available");
      }
    } catch {
      try {
        const textarea = document.createElement("textarea");
        textarea.value = str;
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        textarea.setAttribute("readonly", "");
        document.body.appendChild(textarea);
        textarea.select();
        document.execCommand("copy");
        document.body.removeChild(textarea);
        setCopyFeedback("copied");
      } catch {
        setCopyFeedback("failed");
      }
    }
    copyFeedbackTimeoutRef.current = setTimeout(() => setCopyFeedback(null), 2000);
  }, []);

  function renderPidSection(pid: number, depth: number) {
    const eventsForPid = eventsByPid[pid] ?? [];
    if (eventsForPid.length === 0) return null;

    const info = procTable[String(pid)];
    const comm = info?.Comm ?? "";
    const label = comm ? `PID ${pid} · ${comm}` : `PID ${pid}`;

    return (
      <div key={pid} className="timeline-pid-section" style={{ marginLeft: depth * 16 }}>
        <div className="timeline-pid-header">{label}</div>
        {eventsForPid.map((ev, i) => {
          const eventKey = `${ev.type}-${ev.pid ?? 0}-${ev.ts_ns}-${i}`;
          const isExpanded = expandedEventKey === eventKey;
          const isFork = ev.type === "fork";
          const childPid = isFork ? ev.pid : null;
          const childExpanded = childPid != null && expandedChildPids.has(childPid);

          const groupId = getGroupForType(ev.type ?? "");
          const primary = isPrimarySyscall(ev.type ?? "");
          const isCommonAndRareMode = highlightRare && commonTypesInFiltered.has(ev.type ?? "");
          const rowClasses = [
            "timeline-row",
            `timeline-row-group-${groupId}`,
            primary ? "timeline-row-primary" : "timeline-row-secondary",
            isCommonAndRareMode ? "timeline-row-rare-gray" : "",
          ].filter(Boolean).join(" ");

          return (
            <div key={eventKey}>
              <div
                className={rowClasses}
                onClick={() => setExpandedEventKey((k) => (k === eventKey ? null : eventKey))}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setExpandedEventKey((k) => (k === eventKey ? null : eventKey));
                  }
                }}
              >
                <span className="timeline-row-toggle" aria-label={isExpanded ? "Collapse" : "Expand"}>
                  {isExpanded ? "▼" : "▶"}
                </span>
                <span className="timeline-row-ts">{formatTs(ev.ts_iso)}</span>
                <span className="timeline-row-dot" aria-hidden />
                <span className="badge">{ev.type}</span>
              {ev.pid != null && <span className="badge">pid {ev.pid}</span>}
              {ev.match_type != null && ev.match_type !== "" && (
                <span className="badge timeline-match-badge" style={{ background: "#2d5016", color: "#e0ffc8" }}>
                  match
                </span>
              )}
              </div>
              {isExpanded && (
                <div className="timeline-detail">
                  <pre>{JSON.stringify(ev, null, 2)}</pre>
                  <div className="timeline-detail-actions">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyEventJson(ev);
                      }}
                    >
                      {copyFeedback === "copied" ? "Copied!" : copyFeedback === "failed" ? "Copy failed" : "Copy JSON"}
                    </button>
                  </div>
                </div>
              )}
              {isFork && childPid != null && (eventsByPid[childPid]?.length ?? 0) > 0 && (
                <div className="timeline-child-block">
                  <button
                    type="button"
                    className="timeline-child-toggle"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleChild(childPid);
                    }}
                    aria-label={childExpanded ? "Collapse child" : "Expand child"}
                    title={childExpanded ? "Collapse child process" : "Expand child process"}
                  >
                    {childExpanded ? "▼" : "▶"}
                  </button>
                  <div
                    className="timeline-child-header"
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleChild(childPid);
                    }}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        toggleChild(childPid);
                      }
                    }}
                  >
                    PID {childPid} ({eventsByPid[childPid].length} events)
                  </div>
                  {childExpanded && (
                    <div className="timeline-child-body">
                      {renderPidSection(childPid, depth + 1)}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    );
  }

  return (
    <div>
      <div className="timeline-toolbar" ref={categoryDropdownsRef}>
        {EVENT_GROUPS.map(({ heading, groupId, types }) => {
          const isOpen = openCategory === heading;
          const activeInGroup = types.filter((t) => filters[t]).length;
          return (
            <div key={heading} className="timeline-category-dropdown">
              <button
                type="button"
                className={`timeline-filter-trigger timeline-filter-trigger-${groupId} ${isOpen ? "timeline-filter-trigger-open" : ""}`}
                onClick={() => setOpenCategory(isOpen ? null : heading)}
                aria-expanded={isOpen}
                aria-haspopup="true"
              >
                {heading}
                <span className="timeline-filter-chevron" aria-hidden>{isOpen ? "▲" : "▼"}</span>
                <span className="timeline-filter-badge">{activeInGroup}/{types.length}</span>
              </button>
              {isOpen && (
                <div className="timeline-filter-panel">
                  <div className="timeline-filter-group-checkboxes">
                    {types.map((t) => (
                      <label key={t} className="timeline-filter-checkbox">
                        <input
                          type="checkbox"
                          checked={filters[t]}
                          onChange={(e) => setFilter(t, e.target.checked)}
                        />
                        <span className={`timeline-group-swatch timeline-group-swatch-${groupId} ${isPrimarySyscall(t) ? "timeline-group-swatch-primary" : "timeline-group-swatch-secondary"}`} />
                        <span>{t}</span>
                      </label>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
        <label className="timeline-highlight-rare">
          <input
            type="checkbox"
            checked={highlightRare}
            onChange={(e) => setHighlightRare(e.target.checked)}
          />
          Highlight rare
        </label>
      </div>
      <div className="timeline-scroll">
        {filtered.length === 0 ? (
          <div style={{ color: "#a0a0a0", fontSize: 12 }}>
            {events.length === 0 ? (
              <p>No events yet. Start the daemon with the agent&apos;s PID, then run a task (e.g. web search). Events will stream here in real time.</p>
            ) : (
              <p>
                No events match the current filters.
                {selectedPid != null && onClearSelection && (
                  <> <button type="button" onClick={onClearSelection} style={{ marginLeft: 4 }}>Show all</button> to clear process filter.</>
                )}
                {" "}Or enable more event types above (connect, ssl, read, etc.).
              </p>
            )}
          </div>
        ) : (
          pidsWithEventsInTreeOrder.map(({ pid, depth }) => renderPidSection(pid, depth))
        )}
      </div>
    </div>
  );
}
