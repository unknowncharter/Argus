"use client";

import { useMemo } from "react";
import type { SSLEventRec } from "./types";

const RECENT_COUNT = 7;

function formatTime(tsNs: number): string {
  const ms = tsNs / 1e6;
  const d = new Date(ms);
  return d.toISOString().slice(11, 23);
}

function parseMethodAndEndpoint(snippet: string | undefined, direction: string): { method: string; endpoint: string } {
  if (!snippet?.trim()) return { method: direction.toUpperCase(), endpoint: "-" };  const firstLine = snippet.split("\n")[0]?.trim() ?? "";
  const match = firstLine.match(/^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)/i);
  if (match) return { method: match[1].toUpperCase(), endpoint: match[2] };
  if (snippet.trimStart().startsWith("{")) return { method: direction.toUpperCase(), endpoint: "JSON" };
  return { method: direction.toUpperCase(), endpoint: firstLine.slice(0, 40) || "-" };}

export function RecentApiStrip({ sslEvents }: { sslEvents: SSLEventRec[] }) {
  const rows = useMemo(
    () =>
      sslEvents
        .slice(-RECENT_COUNT)
        .reverse()
        .map((ev) => {
          const { method, endpoint } = ev.Binary
            ? { method: "-", endpoint: "Binary" }            : parseMethodAndEndpoint(ev.Snippet, ev.Direction);
          return {
            key: `${ev.Ts}-${ev.Pid}-${ev.Direction}`,
            time: formatTime(ev.Ts),
            pid: ev.Pid,
            method: ev.Binary ? "-" : method,            endpoint,
            size: ev.Nbytes,
            direction: ev.Direction,
          };
        }),
    [sslEvents]
  );

  if (rows.length === 0) {
    return (
      <div className="recent-api-strip recent-api-strip-empty">
        No API calls captured yet.
      </div>
    );
  }

  return (
    <div className="recent-api-strip">
      <h3 className="recent-api-strip-title">Recent activity</h3>
      <div className="recent-api-table-wrap">
        <table className="recent-api-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>PID</th>
              <th>Dir</th>
              <th>Method</th>
              <th>Endpoint</th>
              <th>Size</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key} className={`recent-api-row recent-api-row-${r.direction}`}>
                <td className="recent-api-time">{r.time}</td>
                <td className="recent-api-pid">{r.pid}</td>
                <td className="recent-api-dir">{r.direction}</td>
                <td className="recent-api-method">{r.method}</td>
                <td className="recent-api-endpoint" title={r.endpoint}>{r.endpoint}</td>
                <td className="recent-api-size">{r.size} B</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
