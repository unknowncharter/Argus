"use client";

import { useState, useMemo } from "react";
import type { SSLEventRec } from "./types";

const CAP = 500;

function splitHeadersAndBody(snippet: string): { headers: string; body: string } {
  const normalized = snippet.replace(/\r\n/g, "\n");
  const double = normalized.indexOf("\n\n");
  if (double === -1) return { headers: "", body: snippet };
  return {
    headers: normalized.slice(0, double).trim(),
    body: normalized.slice(double + 2).trim(),
  };
}

function extractUserPrompt(snippet: string): string | null {
  if (!snippet?.trim()) return null;
  try {
    const obj = JSON.parse(snippet) as Record<string, unknown>;
    const messages = obj?.messages as Array<{ role?: string; content?: string }> | undefined;
    if (Array.isArray(messages)) {
      for (let i = messages.length - 1; i >= 0; i--) {
        const msg = messages[i];
        if (msg?.role === "user" && typeof msg.content === "string") {
          return msg.content;
        }
      }
    }
    if (typeof obj?.prompt === "string") return obj.prompt;
    if (typeof obj?.input === "string") return obj.input;
  } catch {
  }
  return null;
}

function extractTaskLine(fullUserContent: string): string | null {
  if (!fullUserContent?.trim()) return null;
  const prefix = "Please solve this issue: ";
  const idx = fullUserContent.indexOf(prefix);
  if (idx === -1) return null;
  const after = fullUserContent.slice(idx + prefix.length);
  const end = after.indexOf("\n");
  return end === -1 ? after.trim() : after.slice(0, end).trim();
}

export function PromptsPanel({
  sslEvents,
  searchQuery,
  selectedPid,
}: {
  sslEvents: SSLEventRec[];
  searchQuery: string;
  selectedPid: number | null;
}) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [modalTab, setModalTab] = useState<"headers" | "body">("body");
  const [showOnlyTx, setShowOnlyTx] = useState(true);
  const [showOnlyUnique, setShowOnlyUnique] = useState(false);

  const filtered = useMemo(() => {
    let list = sslEvents;
    if (showOnlyTx) {
      list = list.filter((e) => e.Direction === "tx");
    }
    if (selectedPid != null) {
      list = list.filter((e) => e.Pid === selectedPid);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((e) => {
        if (e.Binary) return false;
        return e.Snippet?.toLowerCase().includes(q);
      });
    }
    list = list.slice(-CAP).reverse();

    if (showOnlyUnique && list.length > 0) {
      const keyOf = (ev: SSLEventRec) => {
        const task = ev.Snippet ? extractTaskLine(extractUserPrompt(ev.Snippet) ?? "") : null;
        return `${ev.Pid}-${ev.Direction}-${task ?? ev.Snippet?.slice(0, 200) ?? ev.Ts}`;
      };
      const byKey = new Map<string, SSLEventRec>();
      for (const ev of list) {
        const key = keyOf(ev);
        const existing = byKey.get(key);
        if (!existing || (ev.Snippet?.length ?? 0) > (existing.Snippet?.length ?? 0)) {
          byKey.set(key, ev);
        }
      }
      list = Array.from(byKey.values()).sort((a, b) => a.Ts - b.Ts);
    }

    return list;
  }, [sslEvents, selectedPid, searchQuery, showOnlyTx, showOnlyUnique]);

  return (
    <div className="prompts-panel">
      <p className="prompts-panel-desc">
        TX = request (user prompt) · RX = response (intercepted at SSL_write / SSL_read). One request can appear as multiple TX rows when the client sends the body in chunks.
      </p>
      <div className="prompts-panel-options">
        <label className="prompts-panel-option">
          <input
            type="checkbox"
            checked={showOnlyTx}
            onChange={(e) => setShowOnlyTx(e.target.checked)}
          />
          Show only prompts (TX)
        </label>
        <label className="prompts-panel-option">
          <input
            type="checkbox"
            checked={showOnlyUnique}
            onChange={(e) => setShowOnlyUnique(e.target.checked)}
          />
          Show only unique (by task)
        </label>
      </div>
      <div className="prompts-panel-list">
        {filtered.length === 0 ? (
          <div className="prompts-panel-empty">
            No SSL tx/rx snippets yet.
          </div>
        ) : (
          filtered.map((ev, i) => {
            const isBinary = ev.Binary === true;
            const promptText = ev.Direction === "tx" && ev.Snippet ? extractUserPrompt(ev.Snippet) : null;
            const taskLine = promptText ? extractTaskLine(promptText) : null;
            const displayLine = promptText ?? (isBinary ? null : ev.Snippet?.slice(0, 200));
            const hasMore = !isBinary && (ev.Snippet?.length ?? 0) > 200;

            const { headers, body } = !isBinary && ev.Snippet
              ? splitHeadersAndBody(ev.Snippet)
              : { headers: "", body: "" };
            const hasHeaders = headers.length > 0;

            return (
              <div
                key={`${ev.Ts}-${ev.Direction}-${i}`}
                className={`prompt-row-wrapper prompt-row-${i % 2 === 0 ? "even" : "odd"}`}
              >
                <div
                  className={`prompt-row ${ev.Direction}`}
                  onClick={() => {
                    if (isBinary) return;
                    if (expanded === i) setExpanded(null);
                    else { setExpanded(i); setModalTab("body"); }
                  }}
                  style={{ cursor: isBinary ? "default" : "pointer" }}
                >
                  <span className="badge" style={{ marginRight: 8 }}>
                    {ev.Direction}
                  </span>
                  <span className="badge">pid {ev.Pid}</span>
                  <span style={{ color: "#a0a0a0", marginLeft: 8 }}>
                    {ev.Nbytes} bytes
                  </span>
                  <div style={{ marginTop: 4 }}>
                    {isBinary ? (
                      <em style={{ color: "#a0a0a0" }}>Binary content ({ev.Nbytes} bytes)</em>
                    ) : taskLine ? (
                      <>
                        <strong>Task:</strong> {taskLine}
                      </>
                    ) : promptText ? (
                      <>
                        <strong>User prompt:</strong> {promptText.slice(0, 300)}
                        {promptText.length > 300 ? "…" : ""}
                      </>
                    ) : (
                      <>
                        {displayLine}
                        {hasMore ? "…" : ""}
                      </>
                    )}
                  </div>
                </div>
                {expanded === i && !isBinary && (
                  <div
                    className="modal-overlay"
                    onClick={() => { setExpanded(null); setModalTab("body"); }}
                  >
                    <div
                      className="modal modal-prompts"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="modal-prompts-meta">
                        <span className="badge">{ev.Direction}</span> pid {ev.Pid}
                        {" "}- {ev.Nbytes} bytes                      </div>
                      <div className="modal-prompts-tabs">
                        {hasHeaders && (
                          <button
                            type="button"
                            className={`modal-prompts-tab ${modalTab === "headers" ? "modal-prompts-tab-active" : ""}`}
                            onClick={() => setModalTab("headers")}
                          >
                            Headers
                          </button>
                        )}
                        <button
                          type="button"
                          className={`modal-prompts-tab ${modalTab === "body" ? "modal-prompts-tab-active" : ""}`}
                          onClick={() => setModalTab("body")}
                        >
                          {hasHeaders ? "Body" : "Content"}
                        </button>
                      </div>
                      <div className="modal-prompts-content">
                        {modalTab === "headers" ? (
                          <pre>{headers}</pre>
                        ) : (
                          <pre>{(body || ev.Snippet) ?? ""}</pre>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
