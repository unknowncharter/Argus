"use client";

import { useState } from "react";
import { useObserverState } from "./useObserverState";
import { Timeline } from "./Timeline";
import { NetworkFlows } from "./NetworkFlows";
import { PromptsPanel } from "./PromptsPanel";
import { RecentApiStrip } from "./RecentApiStrip";

const WS_URL =
  typeof window !== "undefined"
    ? `ws://${window.location.hostname}:7071/ws`
    : "";

type TabId = "analysis" | "timeline" | "network" | "prompts";

const TABS: { id: TabId; label: string }[] = [
  { id: "analysis", label: "Analysis" },
  { id: "timeline", label: "Timeline" },
  { id: "network", label: "Network" },
  { id: "prompts", label: "Prompts" },
];

function formatCount(n: number): string {
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

export default function Home() {
  const [tab, setTab] = useState<TabId>("analysis");
  const state = useObserverState(WS_URL);
  const {
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
  } = state;

  const processCount = Object.keys(procTable).length;
  const flowCount = Object.values(flows).reduce((n, list) => n + list.length, 0);

  const statPills: { label: string; value: number; tab: TabId; className: string }[] = [
    { label: "PROC", value: processCount, tab: "analysis", className: "stat-pill-proc" },
    { label: "EVT", value: events.length, tab: "timeline", className: "stat-pill-evt" },
    { label: "CONN", value: flowCount, tab: "network", className: "stat-pill-conn" },
    { label: "SSL", value: sslEvents.length, tab: "prompts", className: "stat-pill-ssl" },
  ];

  return (
    <div className="dashboard-layout">
      <header className="dashboard-header">
        <span className="app-title">Argus</span>        <span className="dashboard-header-status">
          {connected ? (
            <span className="status-dot status-connected">● Connected</span>
          ) : (
            <span className="status-dot status-disconnected">○ Disconnected</span>
          )}
        </span>
        <div className="dashboard-header-stats">
          {statPills.map(({ label, value, tab, className }) => (
            <button
              key={label}
              type="button"
              className={`stat-pill ${className}`}
              title={`${label}: ${formatCount(value)} - go to ${tab}`}              onClick={() => setTab(tab)}
            >
              {formatCount(value)} {label}
            </button>
          ))}
        </div>
        {tab === "timeline" && (
          <div className="dashboard-header-search-wrap">
            <input
              type="search"
              placeholder="Search timeline…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="dashboard-header-search"
            />
          </div>
        )}
      </header>

      <nav className="dashboard-tabs" role="tablist">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            className={`dashboard-tab ${tab === id ? "dashboard-tab-active" : ""}`}
            onClick={() => setTab(id)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div className="dashboard-body scroll-area">
        {tab === "analysis" && (
          <>
            <section className="dashboard-recent-api">
              <RecentApiStrip sslEvents={sslEvents} />
            </section>

            <section className="analysis-correlation">
              <h2 className="dashboard-panel-heading">Correlation</h2>
              <p className="analysis-correlation-desc">
                Process-to-call and user-intent analysis will appear here once implemented.
              </p>
              <div className="analysis-correlation-placeholder">
                <div className="analysis-placeholder-card">
                  <h3>What process called what</h3>
                  <p>Map of which process triggered which syscalls and network calls.</p>
                </div>
                <div className="analysis-placeholder-card">
                  <h3>User intent</h3>
                  <p>Derived user intent from prompts and agent behavior.</p>
                </div>
              </div>
            </section>
          </>
        )}

        {tab === "timeline" && (
          <section className="dashboard-view-panel">
            <Timeline
              events={events}
              filters={filters}
              setFilter={setFilter}
              searchQuery={searchQuery}
              selectedPid={selectedPid}
              onClearSelection={() => setSelectedPid(null)}
              procTable={procTable}
              children={children}
            />
          </section>
        )}

        {tab === "network" && (
          <section className="dashboard-view-content-only">
            <NetworkFlows
              flows={flows}
              procTable={procTable}
              selectedPid={selectedPid}
              onSelectPid={setSelectedPid}
              onGoToTimeline={(pid) => {
                setSelectedPid(pid);
                setTab("timeline");
              }}
            />
          </section>
        )}

        {tab === "prompts" && (
          <section className="dashboard-view-content-only">
            <PromptsPanel
              sslEvents={sslEvents}
              searchQuery={searchQuery}
              selectedPid={selectedPid}
            />
          </section>
        )}
      </div>
    </div>
  );
}
