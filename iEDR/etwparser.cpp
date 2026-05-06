#include "etwparser.h"

// hand over schema for parsing
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    g_trace_started = true;
    // parse_etw_event(record, krabs::schema(record, trace_context.schema_locator));
}