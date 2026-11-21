#!/usr/bin/env bash
# Tableau de bord EN DIRECT de l'infrastructure, dans tmux (4 panneaux rafraîchis toutes les 2 s) :
#   carte vivante | connexions établies | tunnel WireGuard | rejets du pare-feu
# Usage : tools/infra-dashboard.sh        (Ctrl-b d pour détacher, tmux kill-session -t zt pour fermer)
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tmux >/dev/null || { echo "tmux manquant : sudo apt install -y tmux"; exit 1; }
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
V="$PY tools/infra-view.py"
tmux kill-session -t zt 2>/dev/null || true
tmux new-session -d -s zt -x "$(tput cols)" -y "$(tput lines)" "$V map --watch 2"
tmux split-window -h -t zt "$V conns --watch 2"
tmux split-window -v -t zt:0.1 "$V wg --watch 3"
tmux split-window -v -t zt:0.0 "$V drops --watch 2"
tmux select-layout -t zt tiled
tmux set -t zt status off
exec tmux attach -t zt
