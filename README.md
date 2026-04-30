# Argus

# Argus

Argus is a runtime security system that detects and blocks indirect prompt injection attacks on LLM agents. It monitors agent subprocesses from outside the application using eBPF kernel tracepoints — no changes to the agent's source code, configuration, or dependencies are required. When a policy violation is detected, Argus terminates the offending subprocess before the attack completes, leaving the agent process and user shell unaffected.

Argus runs on Linux and attaches to any agent process at deploy time.

## Requirements

- **Ubuntu 22.04+** or any Linux with BPF support
- **Root** (the daemon must run as root to load BPF programs)
- **clang**, **llvm**, **libbpf-dev**, **kernel headers**, **Go 1.21+**, **Node.js 18+**

```bash
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) build-essential
```

Install Go and Node from their official sites if your distribution's packages are too old.

## Quick Start

**Build Argus:**

```bash
make build-bpf build-daemon
```

**Run your agent** (example with mini-swe-agent):

```bash
git clone https://github.com/swe-agent/mini-swe-agent.git
cd mini-swe-agent && python3 -m venv .venv && source .venv/bin/activate
pip install -e .
mini -t "your task here"
```

**Find the agent PID:**

```bash
pgrep -af "python.*mini|mini"
```

**Start Argus** in another terminal (monitoring only):

```bash
sudo ./daemon/daemon --root-pid <PID> --ws-addr 127.0.0.1:7070
```

**Start Argus with blocking enabled:**

```bash
sudo ./daemon/daemon --root-pid <PID> --ws-addr 127.0.0.1:7070 --block --block-budget 5
```

**Pid-file mode** (attach before the agent starts, avoids a PID race):

```bash
sudo ./daemon/daemon --pid-file /tmp/agent.pid --ws-addr 127.0.0.1:7070 --block
```

See `benchmark/scripts/run_task.sh` for a wrapper that writes the PID file before `exec`-ing the agent.

## Web UI

Argus includes an optional web UI for real-time visibility into agent behavior.

```bash
make build-ui
make run-ui
```

Open **http://localhost:3000**. The UI connects to the daemon's WebSocket at `ws://127.0.0.1:7070/ws` by default.

**Tabs:**
- **Analysis** — live event counts and a feed of recent activity
- **Timeline** — every kernel event (fork, exec, exit, connect, file open) with filters and search
- **Network** — outbound connections grouped by process
- **Prompts** — decrypted LLM request and response snippets captured via OpenSSL uprobes

`Authorization: Bearer …` headers and `sk-…` API keys are redacted in the UI and in all daemon-side logs.

## Daemon Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--root-pid` | — | PID of the agent process to monitor (and its full subprocess tree) |
| `--pid-file` | — | Path to a file the agent writes its PID to; daemon waits until the file exists |
| `--ws-addr` | `127.0.0.1:7070` | WebSocket address for the UI and pipeline |
| `--block` | off | Enable active enforcement — kill offending subprocesses on policy violation |
| `--block-budget` | 5 | Maximum number of blocking actions per session before enforcement stops |
| `--max-events` | — | Ring buffer event limit |
| `--snippet-max-chars` | — | Max characters captured per LLM prompt/response snippet |
| `--debug-dim3` | off | Verbose debug output |

The semantic auditor (LLM-based deviation detection) is enabled by setting environment variables before starting the daemon:

```bash
export ARGUS_AUDITOR_URL=https://api.openai.com/v1/chat/completions
export ARGUS_AUDITOR_API_KEY=your_key
export ARGUS_AUDITOR_MODEL=gpt-4o-mini
sudo -E ./daemon/daemon --root-pid <PID> --block
```

## Build

```bash
make build-bpf       # compile eBPF programs
make build-daemon    # compile Go daemon binary
make build-ui        # build Next.js UI
make deps            # print dependency hints (does not install)
```

After any change to `bpf/` run `make build-bpf` before rebuilding the daemon.

## Benchmark

Argus is evaluated using **ORBIT** (OS-level Runtime Benchmark for Injection Threats), an open benchmark for testing OS-level defenses against indirect prompt injection. ORBIT covers 7 attack suites across exfiltration, command injection, and monitoring evasion scenarios, with support for baseline, correlation, and blocking evaluation modes.

See [`benchmark/README.md`](benchmark/README.md) for full details and run commands.

## Repository Layout

| Path | Purpose |
|------|---------|
| `bpf/` | eBPF programs — kernel tracepoints that emit events into a ring buffer |
| `daemon/` | Go daemon — loads BPF, tracks process trees, enforces policy, serves WebSocket API |
| `ui/` | Next.js web UI — Analysis, Timeline, Network, Prompts |
| `benchmark/` | ORBIT benchmark suites and evaluation scripts |
| `scripts/` | Integration and helper shell scripts |
| `configs/` | Configuration notes |

Only the process tree rooted at the specified PID is observed. Everything outside that tree is ignored.

## Troubleshooting

**Timeline has events but Network and Prompts stay empty** — the PID you passed may not be the process making HTTPS calls (e.g. you attached the shell instead of the Python process). Use `pgrep -af` to find the process running the agent binary and reattach.

**Prompts never appear** — Argus captures TLS traffic via OpenSSL uprobes. If the agent uses a different TLS stack (e.g. BoringSSL or a Go TLS implementation), traffic will not appear in the Prompts tab. Check the daemon log for SSL-related lines after an API call.

**BPF fails to load** — ensure `kernel.perf_event_paranoid` is set permissively and that kernel headers match the running kernel:

```bash
sudo sysctl -w kernel.perf_event_paranoid=-1
sudo apt-get install linux-headers-$(uname -r)
```
