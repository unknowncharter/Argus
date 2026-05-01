#!/usr/bin/env bash
echo "Killing stale daemon processes..."
sudo -n pkill -KILL -f "daemon/daemon" 2>/dev/null || true
sleep 2
echo "Remaining daemon processes:"
ps aux | grep "daemon/daemon" | grep -v grep || echo "None"
