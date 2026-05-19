#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "cxxopts.h"

#include <iostream>
#include <vector>

#include "iEDR.h"
#include "etwreader.h"
#include "utils.h"

bool g_trace_started = false;
bool g_debug = false;
bool g_dev_debug = false;

verbosity_level g_level = MINIMAL;

std::wstring g_attack_path;
bool g_autodetect_attack_path = false;
int g_attack_pid = 0;
std::wstring g_attack_pid_str = L"";
int g_attack_main_tid = 0;


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
    std::cout << BANNER;

    if (!is_admin()) {
        std::cerr << "[!] This program must be run as administrator.\n";
        return 1;
	}

    cxxopts::Options options("iEDR");
    options.set_width(120);

    // PARSER OPTIONS
    options.add_options()
        ("h,help", "Print usage")
        ("d,debug", "Enable debug output", cxxopts::value<bool>()->default_value("false"))
		("v,verbose", "Enable development debug output", cxxopts::value<bool>()->default_value("false"))
        ("a,attack", "The file path of the attack to trace", cxxopts::value<std::string>()) // somehow wstring breaks cxxopts
        ("l,level", "The verbosity level, between 0 (minimal) and 3 (verbose)", cxxopts::value<int>()->default_value("0"));

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
        std::cerr << "[!] Attack path to track is required.\n";
        std::cout << options.help() << "\n";
        return 1;
    }
    else {
		g_attack_path = string_to_wstring(result["attack"].as<std::string>());
        if (g_attack_path.empty()) {
            std::cerr << "[!] Attack path to track cannot be empty.\n";
            return 1;
		}
        if (g_attack_path[g_attack_path.length() - 1] == (L'\\')) {
            g_autodetect_attack_path = true;
			std::wcout << L"[+] Tracking EDR actions against all files in directory: " << g_attack_path << L"\n";
        }
        else {
            std::wcout << L"[+] Tracking EDR actions against attack: " << g_attack_path << L"\n";
        }
    }

    if (result.count("verbose")) {
        g_dev_debug = true;
        std::cout << "[+] Development debug output enabled.\n";
    }
    if (result.count("debug")) {
        g_debug = true;
        std::cout << "[+] Debug output enabled.\n";
	}

    if (result.count("level")) {
        int level = result["level"].as<int>();
        if (level < 0 || level > 2) {
            std::cerr << "[!] Invalid verbosity level. Please provide a value between 0 and 2.\n";
            return 1;
		}
        g_level = static_cast<verbosity_level>(level);
    }
    else {
        g_level = MINIMAL;
    }
    std::cout << "[+] Verbosity level set to: " << g_level << "\n";

    // start ETW traces for monitoring
    std::vector<HANDLE> threads;
    if (!start_etw_traces(threads)) {
        std::cerr << "[!] EDRi: Failed to start ETW traces.\n";
        return 1;
    }

    // temporary solution, wait for g_trace_started == true and exit again
    int wait_counter = 0;
    while (!g_trace_started) {
        if (g_debug && wait_counter % 50 == 0) {
            std::cout << "[+] Waiting for ETW traces to start...\n";
		}
        Sleep(100);
		wait_counter++;
    }

	// wait until user presses enter to stop traces and exit
	std::wcout << L"[+] Traces ready, please store your attack file at " << g_attack_path << L" and execute it to see EDR detections in action.\n";
    // todo nicer print?

    std::cout << "[+] Press Enter to stop ETW traces and exit...\n";
	std::cin.get();
	stop_etw_traces();
	std::cout << "[+] ETW traces stopped, exiting...\n";

    // todo get any events from MDE event log

    // todo print end of analysis

    return 0;
}