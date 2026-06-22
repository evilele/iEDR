#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iostream>
#include <vector>

#include "cxxopts.hpp"

#include "iEDR.h"
#include "etwreader.h"
#include "utils.h"

bool g_trace_started = false;
bool g_debug = false;
bool g_dev_debug = false;

verbosity_level g_level = MINIMAL;

std::wstring g_attack_path;
std::vector<int> g_attack_pids = {};
int g_edr_pid = 0; // TODO add MsSense
int g_attack_main_tid = 0;
SYSTEMTIME g_last_attack_store = {0};

void enable_virtual_terminal_processing() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

bool is_admin() {
    BOOL is_admin = FALSE;
    PSID admin_group = nullptr;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(
        &NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }
    return is_admin == TRUE;
}

int main(int argc, char* argv[]) {
    enable_virtual_terminal_processing();
    std::cout << BANNER;

    if (!is_admin()) {
        std::wcerr << L"[!] This program must be run as administrator.\n";
        return 1;
	}

    cxxopts::Options options("iEDR");
    options.set_width(120);

    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("d,debug", "Enable debug output", cxxopts::value<bool>()->default_value("false"))
		("v,verbose", "Enable verbose development debug output", cxxopts::value<bool>()->default_value("false"))
        ("a,attack", "The file path of the attack to trace", cxxopts::value<std::string>()) // somehow wstring breaks cxxopts
        ("l,level", "The trace level, between 0 (minimal) and 2 (verbose) events", cxxopts::value<int>()->default_value("0"));

    cxxopts::ParseResult result;
    try {
        result = options.parse(argc, argv);
    }
    catch (const cxxopts::exceptions::parsing& e) {
        std::cerr << "Error parsing options: " << e.what() << "\n";
        std::cout << options.help() << "\n";
        return 1;
    }

    // PARSING
    if (result.count("help")) {
        std::cout << options.help() << "\n";
        return 0;
    }
    if (result.count("attack") == 0) {
        std::wcerr << L"[!] Attack path to track is required.\n";
        std::cout << options.help() << "\n";
        return 1;
    }
    else {
		g_attack_path = string_to_wstring(result["attack"].as<std::string>());
        if (g_attack_path.empty()) {
            std::wcerr << L"[!] Attack path to track cannot be empty.\n";
            return 1;
		}
        if (g_attack_path[g_attack_path.length() - 1] == (L'\\')) {
			std::wcerr << L"[!] Specify a specific filepath not a folder path: " << g_attack_path << L"\n";
            return 1;
        }
        else {
            std::wcout << L"[+] Tracking EDR actions against attack: " << g_attack_path << L"\n";
        }
    }

    if (result.count("verbose")) {
        g_dev_debug = true;
        std::wcout << L"[+] Development debug output enabled.\n";
    }
    if (result.count("debug")) {
        g_debug = true;
        std::wcout << L"[+] Debug output enabled.\n";
	}

    if (result.count("level")) {
        int level = result["level"].as<int>();
        if (level < 0 || level > 2) {
            std::wcerr << L"[!] Invalid verbosity level. Please provide a value between 0 and 2.\n";
            return 1;
		}
        g_level = static_cast<verbosity_level>(level);
    }
    else {
        g_level = MINIMAL;
    }
    std::wcout << L"[+] Verbosity level set to: " << g_level << L"\n";

	g_edr_pid = get_process_id_by_name(MsMpEng);
    if (g_edr_pid == 0) {
        std::wcerr << L"[!] Failed to find " << MsMpEng << L" process.\n";
        return 1;
	}
    if (g_debug) {
        std::wcout << L"[+] Found " << MsMpEng << L" process with PID=" << g_edr_pid << L"\n";
	}

    // start ETW traces for monitoring
    std::vector<HANDLE> threads;
    if (!start_etw_traces(threads)) {
        std::wcerr << L"[!] Failed to start ETW traces.\n";
        return 1;
    }

    std::wcout << L"[+] Starting ETW traces" << std::flush;
    while (!g_trace_started) {
        std::wcout << L"." << std::flush;
        Sleep(300);
    }
    std::wcout << L"\n";
    GetSystemTime(&g_last_attack_store); // set time to not get older events before tool startup
    Sleep(1000); // wait for all traces

	// wait until user presses enter to stop traces and exit
	std::wcout << L"[+] Traces ready, store attack at " << g_attack_path << L"\n";

    std::wcout << L"[+] Enter STOP to stop ETW traces and exit...\n";
    std::wcout << L"[+] Enter RESET to generate a report and continue...\n";
	std::string input;
	while (true) {
		std::getline(std::cin, input);
		if (input == "STOP") {
			break;
		}
        if (input == "RESET") {
            std::wcout << L"[+] Generating report...\n";
            reset_attack_tracking_and_print_evtl_threaded();
		}
	}
	stop_etw_traces();
	std::wcout << L"[+] ETW traces stopped, exiting...\n";

    return 0;
}