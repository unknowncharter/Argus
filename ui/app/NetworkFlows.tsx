"use client";

import { useMemo } from "react";
import type { ProcTable, FlowRec } from "./types";

function shortExe(exe: string): string {
  if (!exe) return "?";
  const parts = exe.split("/");
  return parts[parts.length - 1] || exe;
}

const MAX_DEST_CHIPS = 8;

export function NetworkFlows({
  flows,
  procTable,
  selectedPid,
  onSelectPid,
  onGoToTimeline,
}: {
  flows: Record<string, FlowRec[]>;
  procTable: ProcTable;
  selectedPid: number | null;
  onSelectPid: (p: number | null) => void;
  onGoToTimeline?: (pid: number) => void;
}) {
  const rows = useMemo(() => {
    return Object.entries(flows).map(([pidStr, list]) => {
      const info = procTable[pidStr];
      const exe = shortExe(info?.Exe ?? "");
      const comm = info?.Comm ?? "?";
      const last = list[list.length - 1];
      const destSet = new Set<string>();
      list
        .slice(-20)
        .reverse()
        .forEach((f) => destSet.add(`${f.DstIP}:${f.DstPort}`));
      const destList = Array.from(destSet).slice(0, MAX_DEST_CHIPS);
      return {
        pid: Number(pidStr),
        exe: exe || comm,
        count: list.length,
        destList,
        lastTs: last?.Ts ?? 0,
      };
    });
  }, [flows, procTable]);

  if (rows.length === 0) {
    return (
      <div className="network-flows-empty">
        No outbound connect() yet. API/HTTPS calls from the agent will appear here.
      </div>
    );
  }

  return (
    <div className="network-flows">
      <div className="flow-table">
        <div className="flow-header">
          <span className="flow-col-pid">PID</span>
          <span className="flow-col-exe">Process</span>
          <span className="flow-col-count">Connections</span>
          <span className="flow-col-dests">Destinations</span>
        </div>
        {rows.map((r) => (
          <div
            key={r.pid}
            className={`flow-row ${selectedPid === r.pid ? "flow-row-selected" : ""}`}
            onClick={() => onSelectPid(r.pid)}
          >
            <span className="flow-col-pid">{r.pid}</span>
            <span className="flow-col-exe" title={procTable[String(r.pid)]?.Exe}>
              {r.exe}
            </span>
            <span className="flow-col-count">
              <button
                type="button"
                className="flow-count-badge flow-count-badge-link"
                title="View this process in Timeline"
                onClick={(e) => {
                  e.stopPropagation();
                  onGoToTimeline?.(r.pid);
                }}
              >
                {r.count}
              </button>
            </span>
            <span className="flow-col-dests flow-col-dests-chips">
              {r.destList.length === 0 ? (
                "-"              ) : (
                r.destList.map((dest) => (
                  <span key={dest} className="flow-dest-chip" title={dest}>
                    {dest}
                  </span>
                ))
              )}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
