#!/usr/bin/env bash
# Compile-test patch series. Apply each series on its stable base, build the
# changed .c files with allmodconfig, report errors and new warnings.
# Usage: scripts/build-test.sh <arm64|arm|riscv|x86> [series dir ...]
# Env: LINUX_URL (default armbian/linux), WORK (default ./build-test)
set -uo pipefail
arch=${1:?arch}; shift
[ $# -gt 0 ] || set -- patches/*/ cve/*/*/
case $arch in
	arm64) cross=aarch64-linux-gnu- ;;
	arm) cross=arm-linux-gnueabihf- ;;
	riscv) cross=riscv64-linux-gnu- ;;
	x86) cross= ;;
	*) echo "unknown arch: $arch" >&2; exit 2 ;;
esac
root=$PWD
work=${WORK:-$root/build-test}
src=$work/linux
summary=${GITHUB_STEP_SUMMARY:-/dev/null}
mkdir -p "$work/logs"
[ -d "$src/.git" ] || git init -q "$src"

kmake() { make -s -C "$src" O="$out" ARCH="$arch" CROSS_COMPILE="$cross" -j"$(nproc)" "$@"; }
warnings() { grep -c ': warning:' "$1" || true; }

prepare() { # $1 = base commit
	out=$work/out-$arch-${1:0:12}
	[ -f "$out/.prepared" ] && return 0
	echo "== prepare $arch at ${1:0:12}"
	git -C "$src" fetch -q --depth 1 "${LINUX_URL:-https://github.com/armbian/linux.git}" "$1" &&
		git -C "$src" checkout -qf --detach "$1" &&
		kmake allmodconfig &&
		"$src/scripts/config" --file "$out/.config" --disable WERROR &&
		kmake olddefconfig && kmake prepare && touch "$out/.prepared"
}

fail=0
echo "| Series | $arch | Notes |" >>"$summary"
echo "|---|---|---|" >>"$summary"
# Group by base so each tree is prepared once.
for d in $(for d in "$@"; do [ -f "$d/base" ] && echo "$(cat "$d/base") ${d%/}"; done | sort | cut -d' ' -f2); do
	base=$(cat "$d/base")
	name=${d#cve/}
	log=$work/logs/${name//\//_}.log
	: >"$log"
	if ! prepare "$base" >>"$log" 2>&1; then
		echo "| $name | error | prepare failed |" >>"$summary"; fail=1; continue
	fi
	git -C "$src" checkout -qf --detach "$base" && git -C "$src" clean -qfd
	mapfile -t series < <(grep -v -e '^#' -e '^$' "$d/series.conf")
	# Changed .c files, without arch/ trees of other architectures.
	patches=("${series[@]/#/$root/$d/}")
	# Changed .c files, without arch/ trees of other architectures.
	mapfile -t files < <(sed -n 's|^+++ b/\(.*\.c\)$|\1|p' "${patches[@]}" | sort -u |
		grep -E -v "^arch/" ; sed -n 's|^+++ b/\(arch/'"$arch"'/.*\.c\)$|\1|p' "${patches[@]}" | sort -u)
	declare -A before=()
	for f in "${files[@]}"; do
		[ -f "$src/$f" ] || continue
		kmake "${f%.c}.o" >"$log.base" 2>&1
		before[$f]=$(warnings "$log.base")
	done
	if ! git -C "$src" -c user.name=t -c user.email=t@t am -q "${patches[@]}" >>"$log" 2>&1; then
		git -C "$src" am --abort 2>/dev/null
		echo "| $name | error | does not apply |" >>"$summary"; fail=1; continue
	fi
	result=ok notes=() built=0
	for f in "${files[@]}"; do
		o=${f%.c}.o
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
	unset before
	[ "$built" -eq 0 ] && [ $result = ok ] && result=skipped notes+=("no .c file built for $arch")
	[ $result = error ] && fail=1
	echo "$name: $result ${notes[*]}"
	echo "| $name | $result | ${notes[*]} |" >>"$summary"
done
rm -f "$work"/logs/*.log.base "$work"/logs/*.log.one
exit $fail
