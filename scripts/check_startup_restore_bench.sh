#!/usr/bin/env bash
set -euo pipefail

OUT_FILE="${1:-startup-restore-bench.txt}"
THRESHOLD_RATIO="1.20"
BENCH_EXPR='^BenchmarkServerStartupRestore/(persisted_leaves_only|snapshot_plus_tail)$'

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

RAW_OUT="$WORK_DIR/bench.raw"
PERSISTED_FILE="$WORK_DIR/persisted_ns.txt"
SNAPSHOT_FILE="$WORK_DIR/snapshot_ns.txt"


go test -run '^$' -bench "$BENCH_EXPR" -benchmem -count=3 ./pkg/api/... | tee "$RAW_OUT"

awk -v persisted="$PERSISTED_FILE" -v snapshot="$SNAPSHOT_FILE" '
function emit(target, value) {
	for (i = 1; i <= NF; i++) {
		if ($i == "ns/op" && i > 1) {
			value = $(i - 1)
			print value >> target
			return
		}
	}
}
$1 ~ /^BenchmarkServerStartupRestore\/persisted_leaves_only/ { emit(persisted) }
$1 ~ /^BenchmarkServerStartupRestore\/snapshot_plus_tail/ { emit(snapshot) }
' "$RAW_OUT"

if [[ ! -s "$PERSISTED_FILE" ]]; then
	echo "missing benchmark samples for persisted_leaves_only" >&2
	exit 1
fi
if [[ ! -s "$SNAPSHOT_FILE" ]]; then
	echo "missing benchmark samples for snapshot_plus_tail" >&2
	exit 1
fi

median_from_file() {
	local sample_file="$1"
	mapfile -t samples < <(sort -n "$sample_file")
	local count="${#samples[@]}"
	if (( count == 0 )); then
		echo "0"
		return 0
	fi
	if (( count % 2 == 1 )); then
		printf "%.3f" "${samples[count/2]}"
		return 0
	fi

	awk -v a="${samples[count/2-1]}" -v b="${samples[count/2]}" 'BEGIN { printf "%.3f", (a+b)/2.0 }'
}

persisted_median="$(median_from_file "$PERSISTED_FILE")"
snapshot_median="$(median_from_file "$SNAPSHOT_FILE")"

ratio="$(awk -v snapshot="$snapshot_median" -v persisted="$persisted_median" 'BEGIN {
	if (persisted <= 0) {
		printf "inf"
		exit
	}
	printf "%.6f", snapshot / persisted
}')"

status="pass"
if [[ "$ratio" == "inf" ]] || ! awk -v ratio="$ratio" -v threshold="$THRESHOLD_RATIO" 'BEGIN { exit !(ratio <= threshold) }'; then
	status="fail"
fi

{
	echo "benchmark: startup-restore"
	echo "persisted_leaves_only_ns_op_median: $persisted_median"
	echo "snapshot_plus_tail_ns_op_median: $snapshot_median"
	echo "ratio_snapshot_to_persisted: $ratio"
	echo "threshold_ratio: $THRESHOLD_RATIO"
	echo "status: $status"
} > "$OUT_FILE"

cat "$OUT_FILE"

if [[ "$status" != "pass" ]]; then
	echo "startup restore benchmark gate failed: ratio $ratio exceeds threshold $THRESHOLD_RATIO" >&2
	exit 1
fi
