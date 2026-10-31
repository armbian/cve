#!/usr/bin/env bash
# Compile-test patch series. Apply each series on its stable base, build the
# changed .c files with allmodconfig, report errors and new warnings.
# Usage: scripts/build-test.sh <arm64|arm|riscv|x86> [series dir ...]
# Env: LINUX_URL (default armbian/linux), WORK (default ./build-test),
#      SLOTS (series built in parallel, each in its own tree; default nproc/8),
#      SHARD=i/n (test every n-th series from i, to split the work over n jobs)
set -uo pipefail
arch=${1:?arch}; shift
[ $# -gt 0 ] || set -- patches/*/ cve/*/*/
case $arch in
	arm64) cross=aarch64-linux-gnu- host=aarch64 ;;
	arm) cross=arm-linux-gnueabihf- host=armv7l ;;
	riscv) cross=riscv64-linux-gnu- host=riscv64 ;;
	x86) cross=x86_64-linux-gnu- host=x86_64 ;;
	*) echo "unknown arch: $arch" >&2; exit 2 ;;
esac
[ "$(uname -m)" = "$host" ] && cross=	# native build on a matching host
root=$PWD
work=${WORK:-$root/build-test}
repo=$work/linux
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
cpus=$(nproc)
slots=${SLOTS:-$((cpus / 8))}
[ "$slots" -ge 1 ] || slots=1
mkdir -p "$work"
# A persistent WORK must not fill the disk: start clean below 30 GB free,
# and build one series at a time below 15 GB.
free_gb() { df --output=avail -BG "$work" | tail -1 | tr -dc 0-9; }
if [ "$(free_gb)" -lt 30 ]; then
	echo "$(free_gb) GB free: clearing $work"
	rm -rf "${work:?}"/* && mkdir -p "$work"
fi
[ "$(free_gb)" -ge 15 ] || slots=1
rm -rf "$work/logs" "$work"/rows-* && mkdir -p "$work/logs"
[ -d "$repo/.git" ] || git init -q "$repo"
# WORK belongs to one runner, which runs one job at a time: a lock left by a
# cancelled job is stale.
find "$repo/.git" -maxdepth 3 -name '*.lock' -delete 2>/dev/null

kmake() { make -s -C "$src" O="$out" ARCH="$arch" CROSS_COMPILE="$cross" -j"$jobs" "$@"; }
warnings() { grep -c ': warning:' "$1" || true; }

# Object that compiles $1: the file itself, or the .c in its directory that
# includes it (e.g. kernel/sched/ext.c in build_policy.c).
target() {
	local dir=${1%/*} name=${1##*/} inc
	if ! grep -qsw "${name%.c}.o" "$src/$dir/Makefile" "$src/$dir/Kbuild"; then
		inc=$(grep -lsE "^#[[:space:]]*include \"$name\"" "$src/$dir"/*.c | head -1)
		[ -n "$inc" ] && { echo "$dir/${inc##*/}" | sed 's/\.c$/.o/'; return; }
	fi
	echo "${1%.c}.o"
}

prepare() { # $1 = base commit; in this slot's tree
	out=$work/out-$arch-$slot-${1:0:12}
	[ -f "$out/.prepared" ] && return 0
	echo "== slot $slot: prepare $arch at ${1:0:12}" >&3
	git -C "$src" checkout -qf --detach "$1" &&
		kmake allmodconfig &&
		"$src/scripts/config" --file "$out/.config" --disable WERROR &&
		kmake olddefconfig && kmake prepare && touch "$out/.prepared"
}

exec 3>&1	# progress to the job log; build output goes to logs/

# One slot: its own worktree and build dirs; prints its result rows to $rows.
worker() {
	slot=$1; shift
	src=$work/tree-$slot rows=$work/rows-$slot fail=0
	: >"$rows"
	[ -e "$src/.git" ] || git -C "$repo" worktree add -q --detach "$src" "$(cat "$1/base")" || return 1
	for d in "$@"; do
		base=$(cat "$d/base")
		name=${d#cve/}
		echo "[slot $slot] $name ..."
		log=$work/logs/${name//\//_}.log
		: >"$log"
		if ! prepare "$base" >>"$log" 2>&1; then
			echo "$name: error (prepare failed)"; tail -3 "$log" | sed 's/^/    /'
			echo "| $name | error | prepare failed |" >>"$rows"; fail=1; continue
		fi
		git -C "$src" checkout -qf --detach "$base" && git -C "$src" clean -qfd
		mapfile -t series < <(grep -v -e '^#' -e '^$' "$d/series.conf")
		patches=("${series[@]/#/$root/$d/}")
		# Changed .c files, without arch/ trees of other architectures.
		mapfile -t files < <(sed -n 's|^+++ b/\(.*\.c\)$|\1|p' "${patches[@]}" | sort -u |
			grep -E -v "^(arch|tools)/" ; sed -n 's|^+++ b/\(arch/'"$arch"'/.*\.c\)$|\1|p' "${patches[@]}" | sort -u)
		declare -A before=() obj=() broken=()
		for f in "${files[@]}"; do
			obj[$f]=$(target "$f")
			[ -f "$src/$f" ] || continue
			# A file that does not build alone at base cannot be tested.
			kmake "${obj[$f]}" >"$log.base" 2>&1 || broken[$f]=1
			before[$f]=$(warnings "$log.base")
		done
		if ! git -C "$src" -c user.name=t -c user.email=t@t am -q "${patches[@]}" >>"$log" 2>&1; then
			git -C "$src" am --abort 2>/dev/null
			echo "$name: error (does not apply)"
			echo "| $name | error | does not apply |" >>"$rows"; fail=1; continue
		fi
		result=ok notes=() built=0
		for f in "${files[@]}"; do
			o=${obj[$f]}
			[ -n "${broken[$f]:-}" ] && { notes+=("$f: does not build alone at base"); continue; }
			rm -f "$out/$o"
			if ! kmake "$o" >"$log.one" 2>&1; then
				result=error notes+=("$f: error")
			elif [ -f "$out/$o" ]; then
				built=$((built + 1))
				new=$(( $(warnings "$log.one") - ${before[$f]:-0} ))
				[ "$new" -gt 0 ] && { [ $result = ok ] && result=warning; notes+=("$f: $new new warning(s)"); }
			fi
			{ echo "## $f"; cat "$log.one"; } >>"$log"
		done
		unset before obj broken
		[ "$built" -eq 0 ] && [ $result = ok ] && result=skipped notes+=("no .c file built for $arch")
		[ $result = error ] && fail=1
		echo "$name: $result ${notes[*]}"
		echo "| $name | $result | ${notes[*]} |" >>"$rows"
	done
	return $fail
}

# Sorted by base, so a slot prepares each base once. Fetch every base first.
mapfile -t units < <(for d in "$@"; do [ -f "$d/base" ] && echo "$(cat "$d/base") ${d%/}"; done | sort | cut -d' ' -f2)
if [ -n "${SHARD:-}" ]; then
	mine=()
	for ((k = ${SHARD%/*}; k < ${#units[@]}; k += ${SHARD#*/})); do mine+=("${units[k]}"); done
	units=("${mine[@]}")
fi
[ ${#units[@]} -gt 0 ] || { echo "no series to test"; exit 0; }
[ "$slots" -le ${#units[@]} ] || slots=${#units[@]}
jobs=$(( cpus / slots + 1 ))
git -C "$repo" worktree prune
for b in $(cat "${units[@]/%//base}" | sort -u); do
	git -C "$repo" cat-file -e "$b^{commit}" 2>/dev/null ||
		git -C "$repo" fetch -q --depth 1 "${LINUX_URL:-https://github.com/armbian/linux.git}" "$b" || exit 1
done
# Drop build dirs of bases no longer tested, and trees of slots not used.
bases=" $(cat "${units[@]/%//base}" | cut -c1-12 | sort -u | tr '\n' ' ')"
for o in "$work"/out-*; do
	[ -d "$o" ] && [[ "$bases" != *" ${o##*-} "* ]] && rm -rf "$o"
done
for t in "$work"/tree-*; do
	[ -d "$t" ] && [ "${t##*-}" -ge "$slots" ] && { git -C "$repo" worktree remove --force "$t" 2>/dev/null || rm -rf "$t"; }
done
echo "${#units[@]} series, $slots slot(s), make -j$jobs, $(free_gb) GB free"
pids=()
for ((i = 0; i < slots; i++)); do
	mine=()
	for ((k = i; k < ${#units[@]}; k += slots)); do mine+=("${units[k]}"); done
	worker "$i" "${mine[@]}" & pids+=($!)
done
fail=0
for p in "${pids[@]}"; do wait "$p" || fail=1; done
echo "| Series | $arch | Notes |" >>"$summary"
echo "|---|---|---|" >>"$summary"
sort "$work"/rows-* >>"$summary"
rm -f "$work"/logs/*.log.base "$work"/logs/*.log.one
exit $fail
