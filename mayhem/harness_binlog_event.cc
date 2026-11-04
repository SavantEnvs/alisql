// libFuzzer harness for libbinlogevents: decodes one framed binlog event the way
// the server's reader does (header event_len selects how many bytes belong to the
// event) through the matching Binary_log_event subclass constructor.
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>

#include "libbinlogevents/include/binlog_event.h"
#include "libbinlogevents/include/control_events.h"
#include "libbinlogevents/include/load_data_events.h"
#include "libbinlogevents/include/rows_event.h"
#include "libbinlogevents/include/statement_events.h"

using namespace binary_log;

namespace {

Binary_log_event *decode(Log_event_type type, const char *buf,
                         const Format_description_event *fde) {
  switch (type) {
    case QUERY_EVENT:
      return new Query_event(buf, fde, QUERY_EVENT);
    case STOP_EVENT:
      return new Stop_event(buf, fde);
    case ROTATE_EVENT:
      return new Rotate_event(buf, fde);
    case INTVAR_EVENT:
      return new Intvar_event(buf, fde);
    case APPEND_BLOCK_EVENT:
      return new Append_block_event(buf, fde);
    case DELETE_FILE_EVENT:
      return new Delete_file_event(buf, fde);
    case RAND_EVENT:
      return new Rand_event(buf, fde);
    case XID_EVENT:
      return new Xid_event(buf, fde);
    case USER_VAR_EVENT:
      return new User_var_event(buf, fde);
    case FORMAT_DESCRIPTION_EVENT:
      return new Format_description_event(buf, fde);
    case BEGIN_LOAD_QUERY_EVENT:
      return new Begin_load_query_event(buf, fde);
    case EXECUTE_LOAD_QUERY_EVENT:
      return new Execute_load_query_event(buf, fde);
    case TABLE_MAP_EVENT:
      return new Table_map_event(buf, fde);
    case WRITE_ROWS_EVENT_V1:
    case WRITE_ROWS_EVENT:
      return new Write_rows_event(buf, fde);
    case UPDATE_ROWS_EVENT_V1:
    case UPDATE_ROWS_EVENT:
    case PARTIAL_UPDATE_ROWS_EVENT:
      return new Update_rows_event(buf, fde);
    case DELETE_ROWS_EVENT_V1:
    case DELETE_ROWS_EVENT:
      return new Delete_rows_event(buf, fde);
    case INCIDENT_EVENT:
      return new Incident_event(buf, fde);
    case HEARTBEAT_LOG_EVENT_V2:
      return new Heartbeat_event_v2(buf, fde);
    case IGNORABLE_LOG_EVENT:
      return new Ignorable_event(buf, fde);
    case ROWS_QUERY_LOG_EVENT:
      return new Rows_query_event(buf, fde);
    case GTID_LOG_EVENT:
    case ANONYMOUS_GTID_LOG_EVENT:
      return new Gtid_event(buf, fde);
    case PREVIOUS_GTIDS_LOG_EVENT:
      return new Previous_gtids_event(buf, fde);
    case TRANSACTION_CONTEXT_EVENT:
      return new Transaction_context_event(buf, fde);
    case VIEW_CHANGE_EVENT:
      return new View_change_event(buf, fde);
    case XA_PREPARE_LOG_EVENT:
      return new XA_prepare_event(buf, fde);
    case TRANSACTION_PAYLOAD_EVENT:
      return new Transaction_payload_event(buf, fde);
    default:
      return nullptr;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < LOG_EVENT_MINIMAL_HEADER_LEN) return -1;

  uint32_t event_len;
  memcpy(&event_len, data + EVENT_LEN_OFFSET, sizeof(event_len));
  if (event_len < LOG_EVENT_MINIMAL_HEADER_LEN || event_len > size) return -1;

  if (data[EVENT_TYPE_OFFSET] >= ENUM_END_EVENT) return -1;
  const auto type = static_cast<Log_event_type>(data[EVENT_TYPE_OFFSET]);

  // Exactly event_len bytes, on the heap, so ASan sees any read past the frame.
  std::unique_ptr<char[]> frame(new char[event_len]);
  memcpy(frame.get(), data, event_len);

  static const Format_description_event fde(BINLOG_VERSION, "8.0.44");
  std::unique_ptr<Binary_log_event> ev(decode(type, frame.get(), &fde));
  if (ev == nullptr) return -1;
  if (!ev->header()->get_is_valid()) return -1;
  return 0;
}
