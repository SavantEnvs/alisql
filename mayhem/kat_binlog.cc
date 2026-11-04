// Known-answer probe for libbinlogevents: decodes hand-encoded binlog events and
// prints the decoded fields. mayhem/test.sh compares the output to golden values.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "libbinlogevents/include/binlog_event.h"
#include "libbinlogevents/include/control_events.h"
#include "libbinlogevents/include/statement_events.h"

using namespace binary_log;

static void put(std::vector<char> &v, uint64_t val, int n) {
  for (int i = 0; i < n; i++) v.push_back(static_cast<char>(val >> (8 * i)));
}

static std::vector<char> header(uint8_t type, uint32_t len) {
  std::vector<char> h;
  put(h, 1700000000, 4);
  put(h, type, 1);
  put(h, 42, 4);
  put(h, len, 4);
  put(h, len, 4);
  put(h, 0, 2);
  return h;
}

int main() {
  const Format_description_event fde(BINLOG_VERSION, "8.0.44");

  {
    std::vector<char> b = header(XID_EVENT, 27);
    put(b, 0x0102030405060708ULL, 8);
    Xid_event ev(b.data(), &fde);
    printf("xid valid=%d type=%d xid=%llu\n", ev.header()->get_is_valid(),
           ev.header()->type_code, (unsigned long long)ev.xid);
  }
  {
    std::vector<char> b = header(ROTATE_EVENT, 40);
    put(b, 4, 8);
    const char name[] = "binlog.000001";
    b.insert(b.end(), name, name + sizeof(name) - 1);
    Rotate_event ev(b.data(), &fde);
    printf("rotate valid=%d pos=%llu file=%.*s\n", ev.header()->get_is_valid(),
           (unsigned long long)ev.pos, (int)ev.ident_len, ev.new_log_ident);
  }
  {
    std::vector<char> b = header(QUERY_EVENT, 45);
    put(b, 7, 4);
    put(b, 3, 4);
    put(b, 4, 1);
    put(b, 0x0415, 2);
    put(b, 0, 2);
    const char tail[] = "test\0SELECT 1";
    b.insert(b.end(), tail, tail + sizeof(tail) - 1);
    Query_event ev(b.data(), &fde, QUERY_EVENT);
    printf("query valid=%d thread=%u exec=%u err=%u db=%s sql=%.*s\n",
           ev.header()->get_is_valid(), ev.thread_id, ev.query_exec_time,
           ev.error_code, ev.db, (int)ev.q_len, ev.query);
  }
  return 0;
}
