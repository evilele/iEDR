#include <iostream>
#include <krabs.hpp>

#include "etwreader.h"
#include "etwparser.h"
#include "providers.h"
#include "utils.h"

krabs::user_trace trace_etw(L"iEDR");


void add_trace(const provider& p) {
    krabs::provider<> provider(p.provider_name);
	const std::map<int, event>& events = p.events_to_track.get(g_level);

    if (events.size() > 0) {

        // extract just event ids
        std::vector<unsigned short> event_ids;
        event_ids.reserve(events.size());
        for (auto const& pair : events) {
            event_ids.push_back(pair.first);
        }

        krabs::event_filter filter(event_ids);
        filter.add_on_event_callback(event_callback);
        provider.add_filter(filter);
        trace_etw.enable(provider);

        if (g_debug) {
            std::wcout << L"[+] ETW: Enabling " << p.provider_name << L": ";
            for (auto id : event_ids) {
                std::cout << id << " ";
            }
            std::cout << "\n";
        }
    }
}

DWORD WINAPI t_start_traces(LPVOID param) {
    try {
        for (auto const& p : providers_to_track) {
            add_trace(p.second);
        }

        // trace_start is blocking, hence threaded
        if (g_debug) {
            std::cout << "[+] ETW: Traces registered, starting...\n";
        }
        trace_etw.start();
    }
    catch (const std::exception& e) {
        std::cout << "[!] ETW: Traces exception: " << e.what() << "\n";
    }
    catch (...) {
        std::cout << "[!] ETW: Traces unknown exception\n";
    }

    std::cout << "[+] ETW: Traces thread finished\n";
    return 0;
}

bool start_etw_traces(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, t_start_traces, NULL, 0, NULL);
    if (thread == NULL) {
        std::cerr << "[!] ETW: Could not start ETW thread\n";
        return false;
    }
    threads.push_back(thread);
    return true;
}

void stop_etw_traces() {
    try {
        trace_etw.stop();
    }
    catch (...) {
        std::cerr << "[!] ETW: Failed to stop traces\n";
    }
}