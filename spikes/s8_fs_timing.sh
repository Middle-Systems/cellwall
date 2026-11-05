#!/usr/bin/env bash
# S8: filesystem cost of the two workspace modes. Runs the same small-file workload in a container
# against (a) a bind mount of a host directory and (b) a named volume, and prints a table.
#
#   spikes/s8_fs_timing.sh [--files N] [--npm] [--dir HOST_DIR]
#
# The default workload needs no network: it writes N small files (like a node_modules tree), walks
# and stats them, reads them back, and deletes them. --npm additionally runs a real `npm install`
# (needs registry access from containers). Run it on the host whose answer you want: macOS and
# Windows are where bind mounts cross a VM boundary. On Windows, run it from Git Bash or WSL, and
# pass --dir with a path on the Windows filesystem (for example /c/Users/you/s8) to measure the
# case that matters, and again with a path inside WSL (/home/you/s8) for comparison.
source "$(dirname "$0")/lib.sh"

# Git Bash (MSYS) rewrites anything that looks like a POSIX path in arguments (/work becomes
# C:/Program Files/Git/work) before docker sees it. Turn that off, and give docker a Windows-style
# path for the host directory when cygpath is available.
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'

FILES=20000; NPM=0; HOSTDIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --files) FILES="$2"; shift 2 ;;
    --npm) NPM=1; shift ;;
    --dir) HOSTDIR="$2"; shift 2 ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
done

IMG="${S8_IMAGE:-node:lts-bookworm-slim}"
[ "$NPM" -eq 0 ] && IMG="${S8_IMAGE:-busybox:1.36}"
[ -z "$HOSTDIR" ] && HOSTDIR="$(mktemp -d)" && defer "rm -rf $HOSTDIR"
mkdir -p "$HOSTDIR/bind"
MOUNTDIR="$HOSTDIR"
if command -v cygpath >/dev/null 2>&1; then MOUNTDIR="$(cygpath -m "$HOSTDIR")"; fi
VOL="${RUN_ID}-vol"
docker volume create "$VOL" >/dev/null && defer "docker volume rm -f $VOL"

# Runs inside the container. $1 = workdir. Prints "phase seconds" lines using millisecond clocks.
read -r -d '' WORKLOAD <<'EOS'
now() { read -r up _ < /proc/uptime; echo "${up%.*}${up#*.}0"; }  # milliseconds, 10 ms resolution
t() { local s=$(now); "$@" >/dev/null 2>&1; local e=$(now); echo "$NAME $((e - s))"; }
cd "$1" || exit 1
rm -rf w; mkdir w; cd w
write() { i=0; while [ $i -lt $FILES ]; do d=d$((i % 200)); [ -d $d ] || mkdir $d; echo "module.exports = $i;" > $d/f$i.js; i=$((i+1)); done; }
NAME=write_small_files t write
NAME=walk_and_stat t sh -c 'find . -type f | wc -l; find . -type f -exec ls -l {} + | wc -l'
NAME=read_all t sh -c 'find . -type f -exec cat {} + | wc -c'
cd ..
NAME=delete_tree t rm -rf w
if [ "$NPM" = 1 ]; then
  mkdir n && cd n && echo '{"name":"s8","version":"1.0.0","dependencies":{"vite":"5","react":"18","react-dom":"18","typescript":"5"}}' > package.json
  NAME=npm_install t npm install --no-audit --no-fund --loglevel=error
  NAME=npm_ls t npm ls --all
  cd .. && rm -rf n
fi
EOS

run_mode() { # run_mode <label> <mount-arg>; prints measurements, or the engine's output on failure
  local out
  out="$(docker run --rm -e FILES="$FILES" -e NPM="$NPM" -v "$2" -e S8_SCRIPT="$WORKLOAD" "$IMG" \
    sh -c 'eval "$S8_SCRIPT"' sh /work 2>&1)"
  if echo "$out" | grep -qE '^[a-z_]+ [0-9]+$'; then
    echo "$out" | grep -E '^[a-z_]+ [0-9]+$' | sed "s/^/$1 /"
  else
    echo "--- $1: no measurements; docker said:" >&2
    echo "$out" | tail -15 >&2
  fi
}

echo "files=$FILES image=$IMG hostdir=$HOSTDIR"
BIND_OUT="$(run_mode bind "$MOUNTDIR/bind:/work")"
VOL_OUT="$(run_mode volume "$VOL:/work")"
[ -n "$BIND_OUT" ] && [ -n "$VOL_OUT" ] || { echo "no measurements produced for at least one mode (see the output above)"; exit 1; }

printf '\n%-18s %12s %12s %8s\n' phase "bind (ms)" "volume (ms)" "ratio"
for p in $(echo "$BIND_OUT" | awk '{print $2}'); do
  b=$(echo "$BIND_OUT" | awk -v p="$p" '$2==p{print $3}')
  v=$(echo "$VOL_OUT" | awk -v p="$p" '$2==p{print $3}')
  [ -n "$v" ] && awk -v p="$p" -v b="$b" -v v="$v" 'BEGIN{printf "%-18s %12d %12d %7.1fx\n", p, b, v, (v>0? b/v : 0)}'
done
echo
echo "ratio = bind time / volume time; above 1 means the volume is faster."
echo "Record: OS, Docker Desktop version, the --dir used, and this table in docs/spikes.md (S8)."
