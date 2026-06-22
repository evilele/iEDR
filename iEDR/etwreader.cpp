#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <memory>
#include <deque>
#include <krabs.hpp>

#include "etwreader.h"
#include "etwparser.h"
#include "providers.h"
#include "utils.h"

std::deque<krabs::provider<>> g_active_providers;
std::deque<krabs::event_filter> g_active_filters;

krabs::user_trace trace_etw(L"iEDR");


void add_trace(const provider& p) {
	const std::vector<event>& events = p.events_to_track.get(g_level);

    if (events.empty()) {
		return; // no events to track for this provider, skip it
    }

    // extract just event ids
    std::vector<unsigned short> event_ids;
    for (auto const& e : events) {
		const auto& event_it = std::find(event_ids.begin(), event_ids.end(), e.id);
        if (event_ids.size() > 0 && event_it != event_ids.end()) { 
            continue; // found duplicate, ids are only required once, even if multiple filters are defined for the same id
		}
        event_ids.push_back(e.id);
    }
   
    // create filter and store them in global deque
    g_active_filters.emplace_back(event_ids);
    auto& events_filter = g_active_filters.back();
    events_filter.add_on_event_callback(event_callback);

	// create provider and store them in gobal deque
    g_active_providers.emplace_back(p.guid);
    auto& prov = g_active_providers.back();

    // appy filter to provider and enable the provider
    prov.add_filter(events_filter);
    trace_etw.enable(prov);

    if (g_debug) {
        std::wcout << L"[+] ETW enabling " << p.provider_name << L": ";
        for (auto id : event_ids) {
            std::wcout << id << L" ";
        }
        std::wcout << L"\n";
    }
}

DWORD WINAPI t_start_traces(LPVOID param) {
    try {
        for (auto const& p : providers_to_track) {
            add_trace(p);
        }
        if (g_debug) {
            std::wcout << L"[+] ETW traces registered, starting...\n";
        }
        trace_etw.start(); // trace_start is blocking, hence threaded
    }
    catch (const std::exception& e) {
        std::wcout << L"[!] ETW traces exception: " << e.what() << "\n";
    }
    catch (...) {
        std::wcout << L"[!] ETW traces unknown exception\n";
    }

    std::wcout << L"[+] ETW traces thread finished\n";
    return 0;
}

bool start_etw_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::wcerr << L"[!] Could not start ETW thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

void stop_etw_traces() {
    try {
        trace_etw.stop();
        g_active_providers.clear();
        g_active_filters.clear();
    }
    catch (...) {
        std::wcerr << L"[!] Failed to stop ETW traces\n";
    }
}