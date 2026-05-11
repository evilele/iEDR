#pragma once

#include <winnt.h>
#include <vector>

#include "utils.h"

bool with_stack_trace = false;

bool start_etw_traces(std::vector<HANDLE>& threads);
void stop_etw_traces();
