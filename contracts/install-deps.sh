#!/usr/bin/env bash
# Fetches the Solidity dependencies for `contracts/` and `examples/uniswap/contracts/`.
#
# These used to be git submodules. Cargo checks out a git dependency's submodules
# recursively, so every crate depending on this repository fetched them too, and the
# nested sp1-helios chain broke Windows builds downstream with paths over MAX_PATH.
# The Rust crates do not use them, so they are now fetched here, only when needed.
#
# Each dependency is pinned to the commit its submodule pointed at, which is what a
# `git clone --recursive` of this repository built against. (The old
# contracts/foundry.lock listed other commits, but nothing read it.)
#
# Usage: contracts/install-deps.sh [--force]
#
# Re-running is a no-op for dependencies already installed at their pin, nested
# submodules included. A clean checkout at another commit is updated in place, which
# keeps its branches and reflog. A checkout with local changes is left alone and
# reported; --force deletes it and installs from scratch.
set -euo pipefail

force=false
case "${1:-}" in
  "") ;;
  --force) force=true ;;
  *) echo "usage: $0 [--force]" >&2; exit 2 ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# path (relative to the repository root) | repository | commit
deps=(
  "contracts/lib/sp1-helios|https://github.com/succinctlabs/sp1-helios|3ad7783769754a3f07f2d3a92192a79daad0a5ee"
  "examples/uniswap/contracts/lib/forge-std|https://github.com/foundry-rs/forge-std|b8f065fda83b8cd94a6b2fec8fcd911dc3b444fd"
  "examples/uniswap/contracts/lib/sp1-contracts|https://github.com/succinctlabs/sp1-contracts|a6ca9452af7d6175adcef28b634fcae8662ded03"
)

# True when $dir is its own repository at $rev with every nested submodule
# initialized and at the commit its parent records.
installed() {
  local dir=$1 rev=$2 status
  [[ -e "$dir/.git" ]] || return 1
  [[ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" == "$rev" ]] || return 1
  status="$(git -C "$dir" submodule status --recursive)" || return 1
  ! grep -q '^[-+U]' <<<"$status"
}

# Returns 0 when $dir or any initialized nested submodule has uncommitted or
# untracked changes, 1 when clean, and 2 when git cannot read it. A nested
# submodule that is merely at another commit (say, from an interrupted update)
# is not a change: `submodule update` moves it without losing anything.
dirty() {
  local dir=$1 out
  out="$(git -C "$dir" status --porcelain --ignore-submodules=all)" || return 2
  [[ -z "$out" ]] || return 0
  out="$(git -C "$dir" submodule foreach -q --recursive \
    'git status --porcelain --ignore-submodules=all')" || return 2
  [[ -n "$out" ]]
}

install() {
  local path=$1 url=$2 rev=$3
  local dir="$root/$path"

  if installed "$dir" "$rev"; then
    echo "ok"
    return
  fi

  if [[ -e "$dir" ]] && ! $force; then
    if [[ -e "$dir/.git" ]]; then
      local rc=0
      dirty "$dir" || rc=$?
      if ((rc == 0)); then
        echo "has local changes; commit or stash them, or rerun with --force to delete it" >&2
        return 1
      elif ((rc == 2)); then
        echo "is not a readable git repository; rerun with --force to delete it" >&2
        return 1
      fi
    elif [[ -n "$(ls -A "$dir")" ]]; then
      echo "exists but is not a git repository; rerun with --force to delete it" >&2
      return 1
    fi
  fi

  if $force; then
    rm -rf "$dir"
  fi

  echo "fetching @ ${rev:0:7}"
  mkdir -p "$dir"
  [[ -e "$dir/.git" ]] || git -C "$dir" init -q
  if ! git -C "$dir" cat-file -e "$rev^{commit}" 2>/dev/null; then
    git -C "$dir" fetch -q --depth 1 "$url" "$rev"
  fi
  git -C "$dir" -c advice.detachedHead=false checkout -q --detach "$rev"
  git -C "$dir" submodule update -q --init --recursive --depth 1

  installed "$dir" "$rev" || { echo "submodules did not install cleanly" >&2; return 1; }
  echo "installed"
}

# The dependencies are independent, so fetch them in parallel, each logging to its
# own file, then report them in order.
logs="$(mktemp -d)"
trap 'rm -rf "$logs"' EXIT

# Background jobs in a script ignore SIGINT, so Ctrl-C alone would leave the
# fetches running in lib/. On INT or TERM, terminate the whole process group (the
# job subshells and their git processes; this shell ignores it), let them exit,
# then exit with the signal's status.
interrupted() {
  trap '' INT TERM
  kill -TERM 0 2>/dev/null || true
  wait
  exit "$1"
}
trap 'interrupted 130' INT
trap 'interrupted 143' TERM

pids=()
for i in "${!deps[@]}"; do
  IFS='|' read -r path url rev <<<"${deps[$i]}"
  (install "$path" "$url" "$rev") >"$logs/$i" 2>&1 &
  pids+=("$!")
done

failed=0
for i in "${!deps[@]}"; do
  status=0
  wait "${pids[$i]}" || status=$?
  sed "s|^|${deps[$i]%%|*}: |" "$logs/$i"
  ((status == 0)) || failed=1
done
exit "$failed"
