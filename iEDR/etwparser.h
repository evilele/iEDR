#pragma once

#include <krabs.hpp>

extern bool g_trace_started;

void event_callback(const EVENT_RECORD&, const krabs::trace_context&);