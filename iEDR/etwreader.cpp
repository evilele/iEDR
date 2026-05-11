#include <iostream>
#include <krabs.hpp>

#include "etwreader.h"
#include "etwparser.h"
#include "utils.h"

krabs::user_trace trace_etw(L"iEDR");


void add_trace(const provider& prov) {
    krabs::provider<> provider(string_to_wstring(prov.provider_name));
	const std::vector<unsigned short>& event_ids = prov.event_ids.get(g_level);

    krabs::event_filter filter(event_ids);
    //if (with_stack_trace) { provider.trace_flags(provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE); }
    filter.add_on_event_callback(event_callback);
    provider.add_filter(filter);
    trace_etw.enable(provider);

    if (g_debug && event_ids.size() > 0) {
        std::cout << "[+] ETW: Enabling " << prov.provider_name << ": ";
        for (auto id : event_ids) {
            std::cout << id << " ";
        }
        std::cout << "\n";
    }
}

DWORD WINAPI t_start_traces(LPVOID param) {
    try {
        // https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW

        // KERNEL //
		add_trace(kernel_process_provider);
		add_trace(kernel_file_provider);
		add_trace(kernel_network_provider);
		add_trace(kernel_api_provider);

		// ANTIMALWARE //
		add_trace(antimalware_provider);

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