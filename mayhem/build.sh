#!/usr/bin/env bash
#
# mayhem/build.sh — builds, from one MySQL 8.0 source tree (AliSQL):
#   * build/fuzz  : sanitized configure; libbinlogevents + MySQL Router libs and the
#                   upstream router libFuzzer targets, plus our binlog-event harness
#   * build/plain : normal-flags configure; the gunit suites + a known-answer probe
#                   that mayhem/test.sh runs
# Output binaries land in /mayhem: <target> (libFuzzer) and <target>-standalone.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS SRC

cd "$SRC"

# Build-time tools (code generators, configure probes) run sanitized; leak reports from
# them are not what we are testing.
# Event_reader::read<bool>() memcpy()s an arbitrary input byte into a bool, so UBSan's
# `bool` check fires on nearly every malformed event and hides everything behind it.
# Only that one check is relaxed; ASan and the rest of UBSan stay halting.
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=bool"
export ASAN_OPTIONS="detect_leaks=0:${ASAN_OPTIONS:-}"

CMAKE_COMMON=(
  -GNinja
  -DCMAKE_BUILD_TYPE=Release
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
  -DWITH_BOOST="$SRC/extra/boost/boost_1_77_0"
  -DWITH_ZLIB=bundled -DWITH_ZSTD=bundled -DWITH_TIRPC=system
  -DWITH_UNIT_TESTS=ON -DWITH_ROUTER=ON
)

# Router fuzz targets (upstream LIBFUZZER_ADD_TEST executables).
MYSQL_PROTOCOL_CMDS=(client_greeting quit init_schema query list_fields reload statistics
  ping change_user binlog_dump register_replica stmt_prepare stmt_execute
  stmt_param_append_data stmt_close stmt_reset set_option stmt_fetch binlog_dump_gtid
  reset_connection clone binary_datetime binary_time)
ROUTER_FUZZ=(routerfuzz_auth_backend routerfuzz_auth_method_basic routerfuzz_base64 routerfuzz_router_uri
  routerfuzz_router_uri_tostring routertest_fuzz_routing_sql_lexer
  routertest_fuzz_parser_show_warnings)
for c in "${MYSQL_PROTOCOL_CMDS[@]}"; do ROUTER_FUZZ+=("routertest_fuzz_mysql_protocol_$c"); done

# Libraries libbinlogevents needs (same set the upstream gunit binlogevents tests link).
BINLOG_LIBS=(libbinlogstandalone.a libmysys.a libstrings.a libzstd.a libzlib.a libmytime.a libbacktrace.a)

# ---------------------------------------------------------------------------
# 1) sanitized build + fuzz binaries
# ---------------------------------------------------------------------------
FUZZ="$SRC/build/fuzz"
# A reconfigure on top of a cache written by a different compiler path (the image build
# runs under ccache's PATH shims, re-runs do not) loses MySQL's WITH_BOOST; configure fresh.
rm -f "$FUZZ/CMakeCache.txt" "$SRC/build/plain/CMakeCache.txt"
# Release defines NDEBUG, which would compile every assert() out of the fuzzed code; override
# the per-config flags for this tree only (CMAKE_CXX_FLAGS_RELEASE comes after CMAKE_CXX_FLAGS
# on the command line, so -UNDEBUG there would be undone).
cmake -S "$SRC" -B "$FUZZ" "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS_RELEASE="-O1" -DCMAKE_CXX_FLAGS_RELEASE="-O1" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
ninja -C "$FUZZ" -j"$MAYHEM_JOBS" "${ROUTER_FUZZ[@]}" "${BINLOG_LIBS[@]}"

LSAN_OFF="$FUZZ/lsan_off.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$LSAN_OFF"
STANDALONE_MAIN="$FUZZ/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_MAIN"

# Relink an upstream-built fuzz target twice, from the exact link line ninja used:
# once as the libFuzzer binary, once against the run-once driver.
relink_cmake_target() {
  local t="$1" line
  line=$(cd "$FUZZ" && ninja -t commands "$t" | grep -E '^: && ' | tail -1)
  line="${line#: && }"; line="${line%% && *}"
  # shellcheck disable=SC2086
  (cd "$FUZZ" && eval "$(echo "$line" | sed -E "s# -o [^ ]+# -o /mayhem/$t#; s#\$# $LSAN_OFF#")")
  (cd "$FUZZ" && eval "$(echo "$line" | sed -E "s# -o [^ ]+# -o /mayhem/$t-standalone#; s#-fsanitize=fuzzer( |\$)# $STANDALONE_MAIN #g; s#\$# $LSAN_OFF#")")
}
for t in "${ROUTER_FUZZ[@]}"; do relink_cmake_target "$t"; done

# Our binlog-event harness against the sanitized libbinlogevents.
BINLOG_INC=(-DSTANDALONE_BINLOG -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DMYSQL_SERVER
  -I"$FUZZ" -I"$FUZZ/include" -I"$SRC" -I"$SRC/include")
BINLOG_LINK=("$FUZZ/libbinlogstandalone/lib/libbinlogstandalone.a"
  "$FUZZ/archive_output_directory/libmysys.a" "$FUZZ/archive_output_directory/libstrings.a"
  "$FUZZ/archive_output_directory/libmysys.a" "$FUZZ/archive_output_directory/libstrings.a"
  "$FUZZ/archive_output_directory/libzstd.a" "$FUZZ/archive_output_directory/libzlib.a"
  "$FUZZ/archive_output_directory/libmytime.a" -lm -lssl -lcrypto
  "$FUZZ/archive_output_directory/libbacktrace.a")
$CXX -std=c++17 -O1 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "${BINLOG_INC[@]}" \
  -c "$SRC/mayhem/harness_binlog_event.cc" -o "$FUZZ/harness_binlog_event.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ/harness_binlog_event.o" "$LSAN_OFF" \
  "${BINLOG_LINK[@]}" -o /mayhem/fuzz_binlog_event
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ/harness_binlog_event.o" "$STANDALONE_MAIN" "$LSAN_OFF" \
  "${BINLOG_LINK[@]}" -o /mayhem/fuzz_binlog_event-standalone

# ---------------------------------------------------------------------------
# 2) test suite, normal flags (independent tree)
# ---------------------------------------------------------------------------
PLAIN="$SRC/build/plain"
env -u ASAN_OPTIONS cmake -S "$SRC" -B "$PLAIN" "${CMAKE_COMMON[@]}" \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
ninja -C "$PLAIN" -j"$MAYHEM_JOBS" gno_intervals-t gtids-t heartbeat_codec-t \
  transaction_payload_codec-t routertest_http_base64 routertest_router_uri \
  routertest_mysql_protocol_classic_protocol_message routertest_mysql_protocol_classic_protocol_wire \
  "${BINLOG_LIBS[@]}"

PLAIN_LINK=("$PLAIN/libbinlogstandalone/lib/libbinlogstandalone.a"
  "$PLAIN/archive_output_directory/libmysys.a" "$PLAIN/archive_output_directory/libstrings.a"
  "$PLAIN/archive_output_directory/libmysys.a" "$PLAIN/archive_output_directory/libstrings.a"
  "$PLAIN/archive_output_directory/libzstd.a" "$PLAIN/archive_output_directory/libzlib.a"
  "$PLAIN/archive_output_directory/libmytime.a" -lm -lssl -lcrypto
  "$PLAIN/archive_output_directory/libbacktrace.a")
$CXX -std=c++17 -O1 $COVERAGE_FLAGS -DSTANDALONE_BINLOG -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 \
  -DMYSQL_SERVER -I"$PLAIN" -I"$PLAIN/include" -I"$SRC" -I"$SRC/include" \
  "$SRC/mayhem/kat_binlog.cc" "${PLAIN_LINK[@]}" -o "$PLAIN/kat_binlog"
