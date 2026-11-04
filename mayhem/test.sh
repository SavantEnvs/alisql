#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PLAIN="$SRC/build/plain"
BIN="$PLAIN/runtime_output_directory"
PASSED=0 ; FAILED=0 ; SKIPPED=0

# run_gtest <binary> <min-tests>: pass/fail counts come from gtest's own summary lines.
# A binary that prints no summary (missing, crashed, or neutered) counts as one failure.
run_gtest() {
  local bin="$1" min="$2" out p=0 f=0 s=0 ran=0
  if [ ! -x "$BIN/$bin" ]; then echo "MISSING $BIN/$bin" >&2; FAILED=$((FAILED + 1)); return; fi
  out=$("$BIN/$bin" 2>&1) ; echo "$out" | tail -n 4
  ran=$(echo "$out" | sed -nE 's/^\[==========\] ([0-9]+) tests? from .* ran\..*/\1/p' | tail -1)
  p=$(echo "$out" | sed -nE 's/^\[  PASSED  \] ([0-9]+) tests?\./\1/p' | tail -1)
  s=$(echo "$out" | sed -nE 's/^\[  SKIPPED \] ([0-9]+) tests?, listed below:/\1/p' | tail -1)
  f=$(echo "$out" | sed -nE 's/^\[  FAILED  \] ([0-9]+) tests?, listed below:/\1/p' | tail -1)
  if [ -z "$ran" ] || [ -z "$p" ] || [ "$ran" -lt "$min" ]; then
    echo "no usable gtest summary from $bin (ran='${ran}' passed='${p}', need >= $min)" >&2
    FAILED=$((FAILED + 1)); return
  fi
  PASSED=$((PASSED + p)) ; FAILED=$((FAILED + ${f:-0})) ; SKIPPED=$((SKIPPED + ${s:-0}))
}

run_gtest gno_intervals-t 10
run_gtest gtids-t 10
run_gtest heartbeat_codec-t 1
run_gtest transaction_payload_codec-t 1
run_gtest routertest_http_base64 55
run_gtest routertest_router_uri 166
run_gtest routertest_mysql_protocol_classic_protocol_message 206
run_gtest routertest_mysql_protocol_classic_protocol_wire 22

# Known-answer probe: libbinlogevents decoding hand-encoded events.
EXPECTED='xid valid=1 type=16 xid=72623859790382856
rotate valid=1 pos=4 file=binlog.000001
query valid=1 thread=7 exec=3 err=1045 db=test sql=SELECT 1'
GOT=$("$PLAIN/kat_binlog" 2>&1 || true)
n=0
while IFS= read -r want; do
  n=$((n + 1))
  if echo "$GOT" | grep -qxF -- "$want"; then PASSED=$((PASSED + 1)); else
    echo "KAT mismatch: wanted '$want'" >&2; FAILED=$((FAILED + 1)); fi
done <<< "$EXPECTED"
echo "$GOT"

emit_ctrf "alisql-binlogevents-router" "$PASSED" "$FAILED" "$SKIPPED"
