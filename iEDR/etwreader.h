#pragma once

#include <krabs.hpp>
#include <vector>

krabs::user_trace& get_iedr_trace();

bool start_etw_traces(std::vector<HANDLE>& threads);
void stop_etw_traces();
